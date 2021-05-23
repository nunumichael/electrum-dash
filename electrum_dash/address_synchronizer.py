# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import threading
import asyncio
import itertools
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple, NamedTuple, Sequence, List

from aiorpcx import TaskGroup

from . import bitcoin, util
from .bitcoin import COINBASE_MATURITY
from .dash_ps import PSManager
from .dash_ps_util import PSCoinRounds, PS_MIXING_TX_TYPES
from .dash_tx import tx_header_to_tx_type
from .util import profiler, bfh, TxMinedInfo, UnrelatedTransactionException
from .protx import ProTxManager
from .transaction import Transaction, TxOutput, TxInput, PartialTxInput, TxOutpoint, PartialTransaction
from .synchronizer import Synchronizer
from .verifier import SPV
from .blockchain import hash_header
from .i18n import _
from .logging import Logger

if TYPE_CHECKING:
    from .network import Network
    from .wallet_db import WalletDB


TX_HEIGHT_LOCAL = -2
TX_HEIGHT_UNCONF_PARENT = -1
TX_HEIGHT_UNCONFIRMED = 0


class HistoryItem(NamedTuple):
    txid: str
    tx_mined_status: TxMinedInfo
    delta: int
    fee: Optional[int]
    balance: int
    tx_type: int
    islock: Optional[int]
    group_txid: Optional[str]
    group_data: Optional[list]


class TxWalletDelta(NamedTuple):
    is_relevant: bool  # "related to wallet?"
    is_any_input_ismine: bool
    is_all_input_ismine: bool
    delta: int
    fee: Optional[int]


class AddressSynchronizer(Logger):
    """
    inherited by wallet
    """

    network: Optional['Network']
    synchronizer: Optional['Synchronizer']
    verifier: Optional['SPV']

    def __init__(self, db: 'WalletDB'):
        self.db = db
        self.network = None
        Logger.__init__(self)
        # verifier (SPV) and synchronizer are started in start_network
        self.synchronizer = None
        self.verifier = None
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()
        # Transactions pending verification.  txid -> tx_height. Access with self.lock.
        self.unverified_tx = defaultdict(int)
        # true when synchronized
        self.up_to_date = False
        # thread local storage for caching stuff
        self.threadlocal_cache = threading.local()
        self.psman = PSManager(self)
        self.protx_manager = ProTxManager(self)

        self._get_addr_balance_cache = {}

        self.load_and_cleanup()

    def with_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def with_transaction_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.transaction_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def load_and_cleanup(self):
        self.load_local_history()
        self.check_history()
        self.load_unverified_transactions()
        self.remove_local_transactions_we_dont_have()
        self.psman.load_and_cleanup()
        self.protx_manager.load()

    def is_mine(self, address: Optional[str]) -> bool:
        if not address: return False
        return self.db.is_addr_in_history(address)

    def get_addresses(self):
        return sorted(self.db.get_history())

    def get_address_history(self, addr: str) -> Sequence[Tuple[str, int]]:
        """Returns the history for the address, in the format that would be returned by a server.

        Note: The difference between db.get_addr_history and this method is that
        db.get_addr_history stores the response from a server, so it only includes txns
        a server sees, i.e. that does not contain local and future txns.
        """
        h = []
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            related_txns = self._history_local.get(addr, set())
            for tx_hash in related_txns:
                tx_height = self.get_tx_height(tx_hash).height
                islock = self.db.get_islock(tx_hash)
                h.append((tx_hash, tx_height, islock))
        return h

    def get_address_history_len(self, addr: str) -> int:
        """Return number of transactions where address is involved."""
        return len(self._history_local.get(addr, ()))

    def get_txin_address(self, txin: TxInput) -> Optional[str]:
        if isinstance(txin, PartialTxInput):
            if txin.address:
                return txin.address
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        for addr in self.db.get_txo_addresses(prevout_hash):
            d = self.db.get_txo_addr(prevout_hash, addr)
            if prevout_n in d:
                return addr
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].address
        return None

    def get_txin_value(self, txin: TxInput, *, address: str = None) -> Optional[int]:
        if txin.value_sats() is not None:
            return txin.value_sats()
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        if address is None:
            address = self.get_txin_address(txin)
        if address:
            d = self.db.get_txo_addr(prevout_hash, address)
            try:
                v, cb = d[prevout_n]
                return v
            except KeyError:
                pass
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].value
        return None

    def get_txout_address(self, txo: TxOutput) -> Optional[str]:
        return txo.address

    def load_unverified_transactions(self):
        # review transactions that are in the history
        for addr in self.db.get_history():
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_tx(tx_hash, tx_height)

    def start_network(self, network: Optional['Network']) -> None:
        self.network = network
        if self.network is not None:
            self.synchronizer = Synchronizer(self)
            self.verifier = SPV(self.network, self)
            util.register_callback(self.on_blockchain_updated, ['blockchain_updated'])
            self.protx_manager.on_network_start(self.network)
            self.psman.on_network_start(self.network)
            util.register_callback(self.on_dash_islock, ['dash-islock'])

    def on_blockchain_updated(self, event, *args):
        self._get_addr_balance_cache = {}  # invalidate cache
        self.db.process_and_clear_islocks(self.get_local_height())

    def on_dash_islock(self, event, txid):
        if txid in self.db.islocks:
            return
        elif txid in self.unverified_tx or txid in self.db.verified_tx:
            self.logger.info(f'found tx for islock: {txid}')
            dash_net = self.network.dash_net
            if dash_net.verify_on_recent_islocks(txid):
                self.db.add_islock(txid)
                self._get_addr_balance_cache = {}  # invalidate cache
                self.save_db()
                util.trigger_callback('verified-islock', self, txid)

    def find_islock_pair(self, txid):
        if txid in self.db.islocks:
            return
        else:
            dash_net = self.network.dash_net
            if dash_net.verify_on_recent_islocks(txid):
                self.db.add_islock(txid)
                self._get_addr_balance_cache = {}  # invalidate cache
                self.save_db()
                util.trigger_callback('verified-islock', self, txid)

    async def stop(self):
        if self.network:
            try:
                async with TaskGroup() as group:
                    if self.synchronizer:
                        await group.spawn(self.synchronizer.stop())
                    if self.verifier:
                        await group.spawn(self.verifier.stop())
            finally:  # even if we get cancelled
                self.synchronizer = None
                self.verifier = None
                util.unregister_callback(self.on_blockchain_updated)
                self.psman.on_stop_threads()
                util.unregister_callback(self.on_dash_islock)
                self.db.put('stored_height', self.get_local_height())

    def add_address(self, address, ps_ks=False):
        if not self.db.get_addr_history(address):
            if ps_ks:
                self.db.ps_ks_hist[address] = []
            else:
                self.db.history[address] = []
            self.set_up_to_date(False)
        if self.synchronizer:
            self.synchronizer.add(address)

    def get_conflicting_transactions(self, tx_hash, tx: Transaction, include_self=False):
        """Returns a set of transaction hashes from the wallet history that are
        directly conflicting with tx, i.e. they have common outpoints being
        spent with tx.

        include_self specifies whether the tx itself should be reported as a
        conflict (if already in wallet history)
        """
        conflicting_txns = set()
        with self.transaction_lock:
            for txin in tx.inputs():
                if txin.is_coinbase_input():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spending_tx_hash = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                if spending_tx_hash is None:
                    continue
                # this outpoint has already been spent, by spending_tx
                # annoying assert that has revealed several bugs over time:
                assert self.db.get_transaction(spending_tx_hash), "spending tx not in wallet db"
                conflicting_txns |= {spending_tx_hash}
            if tx_hash in conflicting_txns:
                # this tx is already in history, so it conflicts with itself
                if len(conflicting_txns) > 1:
                    raise Exception('Found conflicting transactions already in wallet history.')
                if not include_self:
                    conflicting_txns -= {tx_hash}
            return conflicting_txns

    def add_transaction(self, tx: Transaction, *, allow_unrelated=False) -> bool:
        """
        Returns whether the tx was successfully added to the wallet history.
        Note that a transaction may need to be added several times, if our
        list of addresses has increased. This will return True even if the
        transaction was already in self.db.
        """
        assert tx, tx
        # note: tx.is_complete() is not necessarily True; tx might be partial
        # but it *needs* to have a txid:
        tx_hash = tx.txid()
        if tx_hash is None:
            raise Exception("cannot add tx without txid to wallet history")
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            # NOTE: returning if tx in self.transactions might seem like a good idea
            # BUT we track is_mine inputs in a txn, and during subsequent calls
            # of add_transaction tx, we might learn of more-and-more inputs of
            # being is_mine, as we roll the gap_limit forward
            is_coinbase = tx.inputs()[0].is_coinbase_input()
            tx_height = self.get_tx_height(tx_hash).height
            if not allow_unrelated:
                # note that during sync, if the transactions are not properly sorted,
                # it could happen that we think tx is unrelated but actually one of the inputs is is_mine.
                # this is the main motivation for allow_unrelated
                is_mine = any([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()])
                is_for_me = any([self.is_mine(self.get_txout_address(txo)) for txo in tx.outputs()])
                if not is_mine and not is_for_me:
                    raise UnrelatedTransactionException()
            # Find all conflicting transactions.
            # In case of a conflict,
            #     1. confirmed > mempool > local
            #     2. this new txn has priority over existing ones
            # When this method exits, there must NOT be any conflict, so
            # either keep this txn and remove all conflicting (along with dependencies)
            #     or drop this txn
            conflicting_txns = self.get_conflicting_transactions(tx_hash, tx)
            if conflicting_txns:
                existing_mempool_txn = any(
                    self.get_tx_height(tx_hash2).height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT)
                    for tx_hash2 in conflicting_txns)
                existing_confirmed_txn = any(
                    self.get_tx_height(tx_hash2).height > 0
                    for tx_hash2 in conflicting_txns)
                if existing_confirmed_txn and tx_height <= 0:
                    # this is a non-confirmed tx that conflicts with confirmed txns; drop.
                    return False
                if existing_mempool_txn and tx_height == TX_HEIGHT_LOCAL:
                    # this is a local tx that conflicts with non-local txns; drop.
                    return False
                # keep this txn and remove all conflicting
                for tx_hash2 in conflicting_txns:
                    self.remove_transaction(tx_hash2)
            # add inputs
            def add_value_from_prev_output():
                # note: this takes linear time in num is_mine outputs of prev_tx
                addr = self.get_txin_address(txi)
                if addr and self.is_mine(addr):
                    outputs = self.db.get_txo_addr(prevout_hash, addr)
                    try:
                        v, is_cb = outputs[prevout_n]
                    except KeyError:
                        pass
                    else:
                        self.db.add_txi_addr(tx_hash, addr, ser, v)
                        self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
            for txi in tx.inputs():
                if txi.is_coinbase_input():
                    continue
                prevout_hash = txi.prevout.txid.hex()
                prevout_n = txi.prevout.out_idx
                ser = txi.prevout.to_str()
                self.db.set_spent_outpoint(prevout_hash, prevout_n, tx_hash)
                add_value_from_prev_output()
            # add outputs
            for n, txo in enumerate(tx.outputs()):
                v = txo.value
                ser = tx_hash + ':%d'%n
                scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                self.db.add_prevout_by_scripthash(scripthash, prevout=TxOutpoint.from_str(ser), value=v)
                addr = self.get_txout_address(txo)
                if addr and self.is_mine(addr):
                    self.db.add_txo_addr(tx_hash, addr, n, v, is_coinbase)
                    self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
                    # give v to txi that spends me
                    next_tx = self.db.get_spent_outpoint(tx_hash, n)
                    if next_tx is not None:
                        self.db.add_txi_addr(next_tx, addr, ser, v)
                        self._add_tx_to_local_history(next_tx)
            # add to local history
            self._add_tx_to_local_history(tx_hash)
            # save
            is_new_tx = (tx_hash not in self.db.transactions)
            self.db.add_transaction(tx_hash, tx)
            self.db.add_num_inputs_to_tx(tx_hash, len(tx.inputs()))
            if is_new_tx and self.psman.enabled:
                self.psman._add_tx_ps_data(tx_hash, tx)
            if is_new_tx and not self.is_local_tx(tx_hash) and self.network:
                util.trigger_callback('new_transaction', self, tx)
            return True

    def remove_transaction(self, tx_hash: str) -> None:
        """Removes a transaction AND all its dependents/children
        from the wallet history.
        """
        with self.lock, self.transaction_lock:
            to_remove = {tx_hash}
            to_remove |= self.get_depending_transactions(tx_hash)
            for txid in to_remove:
                self._remove_transaction(txid)

    def _remove_transaction(self, tx_hash: str) -> None:
        """Removes a single transaction from the wallet history, and attempts
         to undo all effects of the tx (spending inputs, creating outputs, etc).
        """
        def remove_from_spent_outpoints():
            # undo spends in spent_outpoints
            if tx is not None:
                # if we have the tx, this branch is faster
                for txin in tx.inputs():
                    if txin.is_coinbase_input():
                        continue
                    prevout_hash = txin.prevout.txid.hex()
                    prevout_n = txin.prevout.out_idx
                    self.db.remove_spent_outpoint(prevout_hash, prevout_n)
            else:
                # expensive but always works
                for prevout_hash, prevout_n in self.db.list_spent_outpoints():
                    spending_txid = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                    if spending_txid == tx_hash:
                        self.db.remove_spent_outpoint(prevout_hash, prevout_n)

        with self.lock, self.transaction_lock:
            self.logger.info(f"removing tx from history {tx_hash}")
            if self.psman.enabled:
                self.psman._rm_tx_ps_data(tx_hash)
            tx = self.db.remove_transaction(tx_hash)
            remove_from_spent_outpoints()
            self._remove_tx_from_local_history(tx_hash)
            for addr in itertools.chain(self.db.get_txi_addresses(tx_hash), self.db.get_txo_addresses(tx_hash)):
                self._get_addr_balance_cache.pop(addr, None)  # invalidate cache
            self.db.remove_txi(tx_hash)
            self.db.remove_txo(tx_hash)
            self.db.remove_tx_fee(tx_hash)
            self.db.remove_verified_tx(tx_hash)
            self.unverified_tx.pop(tx_hash, None)
            if tx:
                for idx, txo in enumerate(tx.outputs()):
                    scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey.hex())
                    prevout = TxOutpoint(bfh(tx_hash), idx)
                    self.db.remove_prevout_by_scripthash(scripthash, prevout=prevout, value=txo.value)

    def get_depending_transactions(self, tx_hash: str) -> Set[str]:
        """Returns all (grand-)children of tx_hash in this wallet."""
        with self.transaction_lock:
            children = set()
            for n in self.db.get_spent_outpoints(tx_hash):
                other_hash = self.db.get_spent_outpoint(tx_hash, n)
                children.add(other_hash)
                children |= self.get_depending_transactions(other_hash)
            return children

    def receive_tx_callback(self, tx_hash: str, tx: Transaction, tx_height: int) -> None:
        self.add_unverified_tx(tx_hash, tx_height)
        self.add_transaction(tx, allow_unrelated=True)
        self.find_islock_pair(tx_hash)

    def receive_history_callback(self, addr: str, hist, tx_fees: Dict[str, int]):
        old_hist_hashes = set()
        with self.lock:
            old_hist = self.get_address_history(addr)
            for tx_hash, height, islock in old_hist:
                if height > TX_HEIGHT_LOCAL:
                    old_hist_hashes.add(tx_hash)
                if (tx_hash, height) not in hist:
                    # make tx local
                    self.unverified_tx.pop(tx_hash, None)
                    self.db.remove_verified_tx(tx_hash)
                    if self.verifier:
                        self.verifier.remove_spv_proof_for_tx(tx_hash)
            self.db.set_addr_history(addr, hist)

        local_tx_hist_hashes = list()
        for tx_hash, tx_height in hist:
            if tx_hash not in old_hist_hashes and self.is_local_tx(tx_hash):
                local_tx_hist_hashes.append(tx_hash)
            # add it in case it was previously unconfirmed
            self.add_unverified_tx(tx_hash, tx_height)
            # if addr is new, we have to recompute txi and txo
            tx = self.db.get_transaction(tx_hash)
            if tx is None:
                continue
            self.add_transaction(tx, allow_unrelated=True)

        # Store fees
        for tx_hash, fee_sat in tx_fees.items():
            self.db.add_tx_fee_from_server(tx_hash, fee_sat)
        # unsubscribe from spent ps coins addresses
        if self.psman.enabled:
            self.psman.unsubscribe_spent_addr(addr, hist)
        # trigger new_transaction cb when local tx hash appears in history
        if self.network:
            for tx_hash in local_tx_hist_hashes:
                self.find_islock_pair(tx_hash)
                tx = self.db.get_transaction(tx_hash)
                if tx:
                    util.trigger_callback('new_transaction', self, tx)

    @profiler
    def load_local_history(self):
        self._history_local = {}  # type: Dict[str, Set[str]]  # address -> set(txid)
        self._address_history_changed_events = defaultdict(asyncio.Event)  # address -> Event
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            self._add_tx_to_local_history(txid)

    @profiler
    def check_history(self):
        hist_addrs_mine = list(filter(lambda k: self.is_mine(k), self.db.get_history()))
        hist_addrs_not_mine = list(filter(lambda k: not self.is_mine(k), self.db.get_history()))
        for addr in hist_addrs_not_mine:
            self.db.remove_addr_history(addr)
        for addr in hist_addrs_mine:
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                if self.db.get_txi_addresses(tx_hash) or self.db.get_txo_addresses(tx_hash):
                    continue
                tx = self.db.get_transaction(tx_hash)
                if tx is not None:
                    self.add_transaction(tx, allow_unrelated=True)

    def remove_local_transactions_we_dont_have(self):
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            tx_height = self.get_tx_height(txid).height
            if tx_height == TX_HEIGHT_LOCAL and not self.db.get_transaction(txid):
                self.remove_transaction(txid)

    def clear_history(self):
        with self.lock:
            with self.transaction_lock:
                self.db.clear_history()
                self._history_local.clear()
                self._get_addr_balance_cache = {}  # invalidate cache

    def get_txpos(self, tx_hash, islock):
        """Returns (height, txpos) tuple, even if the tx is unverified."""
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                return verified_tx_mined_info.height, verified_tx_mined_info.txpos
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                if height > 0:
                    return (height, -1)
                elif not islock:
                    return ((1e10 - height), -1)
                else:
                    return (islock, -1)
            else:
                return (1e10+1, -1)

    def with_local_height_cached(func):
        # get local height only once, as it's relatively expensive.
        # take care that nested calls work as expected
        def f(self, *args, **kwargs):
            orig_val = getattr(self.threadlocal_cache, 'local_height', None)
            self.threadlocal_cache.local_height = orig_val or self.get_local_height()
            try:
                return func(self, *args, **kwargs)
            finally:
                self.threadlocal_cache.local_height = orig_val
        return f

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_history(self, *, domain=None, config=None, group_ps=False) -> Sequence[HistoryItem]:
        # get domain
        if domain is None:
            domain = self.get_addresses()
            domain += self.psman.get_addresses()
        domain = set(domain)
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)  # type: Dict[str, int]
        tx_islocks = {}
        for addr in domain:
            h = self.get_address_history(addr)
            for tx_hash, height, islock in h:
                tx_deltas[tx_hash] += self.get_tx_delta(tx_hash, addr)
                if tx_hash not in tx_islocks:
                    tx_islocks[tx_hash] = islock
        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            tx_mined_status = self.get_tx_height(tx_hash)
            islock = tx_islocks[tx_hash]
            if islock:
                islock_sort = tx_hash if not tx_mined_status.conf else ''
            else:
                islock_sort = ''
            fee = self.get_tx_fee(tx_hash)
            history.append((tx_hash, tx_mined_status, delta, fee,
                            islock, islock_sort))
        # tx_hash = x[0], islock = x[4],  islock_sort = x[5]
        history.sort(key=lambda x: (self.get_txpos(x[0], x[4]), x[5]),
                     reverse=True)
        # 3. add balance
        c, u, x = self.get_balance(domain)
        balance = c + u + x
        h2 = []
        if config:
            def_dip2 = not self.psman.unsupported
            show_dip2 = config.get('show_dip2_tx_type', def_dip2)
        else:
            show_dip2 = True  # for testing
        group_size = 0
        group_h2 = []
        group_txid = None
        group_txids = []
        group_delta = None
        group_balance = None
        hist_len = len(history)
        for i, (tx_hash, tx_mined_status, delta, fee,
                islock, islock_sort) in enumerate(history):
            tx_type = 0
            if show_dip2:
                tx = self.db.get_transaction(tx_hash)
                if tx:
                    raw_bytes = bfh(tx.serialize())
                    tx_type = tx_header_to_tx_type(raw_bytes[:4])
            if (group_ps or show_dip2) and not tx_type:  # prefer ProTx type
                tx_type, completed = self.db.get_ps_tx(tx_hash)

            if group_ps and tx_type in PS_MIXING_TX_TYPES:
                group_size += 1
                group_txids.append(tx_hash)
                if group_size == 1:
                    group_txid = tx_hash
                    group_balance = balance
                if delta is not None:
                    if group_delta is None:
                        group_delta = delta
                    else:
                        group_delta += delta
                if group_size > 1:
                    group_h2.append(
                        HistoryItem(txid=tx_hash,
                                    tx_mined_status=tx_mined_status,
                                    delta=delta, fee=fee, balance=balance,
                                    tx_type=tx_type, islock=islock,
                                    group_txid=group_txid, group_data=[]))
                else:
                    group_h2.append(
                        HistoryItem(txid=tx_hash,
                                    tx_mined_status=tx_mined_status,
                                    delta=delta, fee=fee, balance=balance,
                                    tx_type=tx_type, islock=islock,
                                    group_txid=None, group_data=[]))
                if i == hist_len - 1:  # last entry in the history
                    if group_size > 1:
                        group_data = group_h2[0][-1]  # last tuple element
                        group_data.append(group_delta)
                        group_data.append(group_balance)
                        group_data.append(group_txids)
                    h2.extend(group_h2)
            else:
                if group_size > 0:
                    if group_size > 1:
                        group_data = group_h2[0][-1]  # last tuple element
                        group_data.append(group_delta)
                        group_data.append(group_balance)
                        group_data.append(group_txids)
                    h2.extend(group_h2)
                    group_size = 0
                    group_h2 = []
                    group_txid = None
                    group_txids = []
                    group_delta = None
                    group_balance = None
                h2.append(
                    HistoryItem(txid=tx_hash,
                                tx_mined_status=tx_mined_status,
                                delta=delta, fee=fee, balance=balance,
                                tx_type=tx_type, islock=islock,
                                group_txid=None, group_data=[]))

            balance -= delta
        h2.reverse()

        if balance != 0:
            raise Exception("wallet.get_history() failed balance sanity-check")

        return h2

    def _add_tx_to_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                cur_hist.add(txid)
                self._history_local[addr] = cur_hist
                self._mark_address_history_changed(addr)

    def _remove_tx_from_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                try:
                    cur_hist.remove(txid)
                except KeyError:
                    pass
                else:
                    self._history_local[addr] = cur_hist

    def _mark_address_history_changed(self, addr: str) -> None:
        # history for this address changed, wake up coroutines:
        self._address_history_changed_events[addr].set()
        # clear event immediately so that coroutines can wait() for the next change:
        self._address_history_changed_events[addr].clear()

    async def wait_for_address_history_to_change(self, addr: str) -> None:
        """Wait until the server tells us about a new transaction related to addr.

        Unconfirmed and confirmed transactions are not distinguished, and so e.g. SPV
        is not taken into account.
        """
        assert self.is_mine(addr), "address needs to be is_mine to be watched"
        await self._address_history_changed_events[addr].wait()

    def add_unverified_tx(self, tx_hash, tx_height):
        if self.db.is_in_verified_tx(tx_hash):
            if tx_height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
                with self.lock:
                    self.db.remove_verified_tx(tx_hash)
                if self.verifier:
                    self.verifier.remove_spv_proof_for_tx(tx_hash)
        else:
            with self.lock:
                # tx will be verified only if height > 0
                self.unverified_tx[tx_hash] = tx_height

    def remove_unverified_tx(self, tx_hash, tx_height):
        with self.lock:
            new_height = self.unverified_tx.get(tx_hash)
            if new_height == tx_height:
                self.unverified_tx.pop(tx_hash, None)

    def add_verified_tx(self, tx_hash: str, info: TxMinedInfo):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tx.pop(tx_hash, None)
            self.db.add_verified_tx(tx_hash, info)
        tx_mined_status = self.get_tx_height(tx_hash)
        util.trigger_callback('verified', self, tx_hash, tx_mined_status)

    def get_unverified_txs(self):
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return dict(self.unverified_tx)  # copy

    def undo_verifications(self, blockchain, above_height):
        '''Used by the verifier when a reorg has happened'''
        txs = set()
        with self.lock:
            for tx_hash in self.db.list_verified_tx():
                info = self.db.get_verified_tx(tx_hash)
                tx_height = info.height
                if tx_height > above_height:
                    header = blockchain.read_header(tx_height)
                    if not header or hash_header(header) != info.header_hash:
                        self.db.remove_verified_tx(tx_hash)
                        # NOTE: we should add these txns to self.unverified_tx,
                        # but with what height?
                        # If on the new fork after the reorg, the txn is at the
                        # same height, we will not get a status update for the
                        # address. If the txn is not mined or at a diff height,
                        # we should get a status update. Unless we put tx into
                        # unverified_tx, it will turn into local. So we put it
                        # into unverified_tx with the old height, and if we get
                        # a status update, that will overwrite it.
                        self.unverified_tx[tx_hash] = tx_height
                        txs.add(tx_hash)
        return txs

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        cached_local_height = getattr(self.threadlocal_cache, 'local_height', None)
        if cached_local_height is not None:
            return cached_local_height
        return self.network.get_local_height() if self.network else self.db.get('stored_height', 0)

    def get_tx_height(self, tx_hash: str) -> TxMinedInfo:
        if tx_hash is None:  # ugly backwards compat...
            return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                conf = max(self.get_local_height() - verified_tx_mined_info.height + 1, 0)
                return verified_tx_mined_info._replace(conf=conf)
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            else:
                # local transaction
                return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)

    def is_local_tx(self, tx_hash: str):
        tx_mined_info = self.get_tx_height(tx_hash)
        if tx_mined_info.height == TX_HEIGHT_LOCAL:
            return True
        else:
            return False

    def set_up_to_date(self, up_to_date):
        with self.lock:
            status_changed = self.up_to_date != up_to_date
            self.up_to_date = up_to_date
        if self.network:
            self.network.notify('status')
        if status_changed:
            self.logger.info(f'set_up_to_date: {up_to_date}')

    def is_up_to_date(self):
        with self.lock: return self.up_to_date

    def get_history_sync_state_details(self) -> Tuple[int, int]:
        if self.synchronizer:
            return self.synchronizer.num_requests_sent_and_answered()
        else:
            return 0, 0

    @with_transaction_lock
    def get_tx_delta(self, tx_hash: str, address: str) -> int:
        """effect of tx on address"""
        delta = 0
        # subtract the value of coins sent from address
        d = self.db.get_txi_addr(tx_hash, address)
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.db.get_txo_addr(tx_hash, address)
        for n, (v, cb) in d.items():
            delta += v
        return delta

    def get_wallet_delta(self, tx: Transaction) -> TxWalletDelta:
        """effect of tx on wallet"""
        is_relevant = False  # "related to wallet?"
        num_input_ismine = 0
        v_in = v_in_mine = v_out = v_out_mine = 0
        with self.lock, self.transaction_lock:
            for txin in tx.inputs():
                addr = self.get_txin_address(txin)
                value = self.get_txin_value(txin, address=addr)
                if self.is_mine(addr):
                    num_input_ismine += 1
                    is_relevant = True
                    assert value is not None
                    v_in_mine += value
                if value is None:
                    v_in = None
                elif v_in is not None:
                    v_in += value
            for txout in tx.outputs():
                v_out += txout.value
                if self.is_mine(txout.address):
                    v_out_mine += txout.value
                    is_relevant = True
        delta = v_out_mine - v_in_mine
        if v_in is not None:
            fee = v_in - v_out
        else:
            fee = None
        if fee is None and isinstance(tx, PartialTransaction):
            fee = tx.get_fee()
        return TxWalletDelta(
            is_relevant=is_relevant,
            is_any_input_ismine=num_input_ismine > 0,
            is_all_input_ismine=num_input_ismine == len(tx.inputs()),
            delta=delta,
            fee=fee,
        )

    def get_tx_fee(self, txid: str) -> Optional[int]:
        """ Returns tx_fee or None. Use server fee only if tx is unconfirmed and not mine"""
        # check if stored fee is available
        fee = self.db.get_tx_fee(txid, trust_server=False)
        if fee is not None:
            return fee
        # delete server-sent fee for confirmed txns
        confirmed = self.get_tx_height(txid).conf > 0
        if confirmed:
            self.db.add_tx_fee_from_server(txid, None)
        # if all inputs are ismine, try to calc fee now;
        # otherwise, return stored value
        num_all_inputs = self.db.get_num_all_inputs_of_tx(txid)
        if num_all_inputs is not None:
            # check if tx is mine
            num_ismine_inputs = self.db.get_num_ismine_inputs_of_tx(txid)
            assert num_ismine_inputs <= num_all_inputs, (num_ismine_inputs, num_all_inputs)
            # trust server if tx is unconfirmed and not mine
            if num_ismine_inputs < num_all_inputs:
                return None if confirmed else self.db.get_tx_fee(txid, trust_server=True)
        # lookup tx and deserialize it.
        # note that deserializing is expensive, hence above hacks
        tx = self.db.get_transaction(txid)
        if not tx:
            return None
        fee = self.get_wallet_delta(tx).fee
        # save result
        self.db.add_tx_fee_we_calculated(txid, fee)
        self.db.add_num_inputs_to_tx(txid, len(tx.inputs()))
        return fee

    def get_addr_io(self, address):
        with self.lock, self.transaction_lock:
            h = self.get_address_history(address)
            received = {}
            sent = {}
            for tx_hash, height, islock in h:
                d = self.db.get_txo_addr(tx_hash, address)
                for n, (v, is_cb) in d.items():
                    received[tx_hash + ':%d'%n] = (height, v, is_cb, islock)
            for tx_hash, height, islock in h:
                l = self.db.get_txi_addr(tx_hash, address)
                for txi, v in l:
                    sent[txi] = (height, islock)
        return received, sent


    def get_addr_outputs(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        coins, spent = self.get_addr_io(address)
        out = {}
        psman = self.psman
        if psman.enabled:
            ps_origin_addrs = self.db.get_ps_origin_addrs()
        else:
            ps_origin_addrs = []
        for prevout_str, v in coins.items():
            ps_rounds = None
            ps_denom = self.db.get_ps_denom(prevout_str)
            if ps_denom:
                ps_rounds = ps_denom[2]
            if ps_rounds is None:
                ps_collateral = self.db.get_ps_collateral(prevout_str)
                if ps_collateral:
                    ps_rounds = int(PSCoinRounds.COLLATERAL)
            if (psman.group_origin_coins_by_addr
                    and ps_rounds is None
                    and ps_origin_addrs
                    and address in ps_origin_addrs):
                ps_rounds = int(PSCoinRounds.MIX_ORIGIN)
            if ps_rounds is None:
                ps_other = self.db.get_ps_other(prevout_str)
                if ps_other:
                    ps_rounds = int(PSCoinRounds.OTHER)
            tx_height, value, is_cb, islock = v
            prevout = TxOutpoint.from_str(prevout_str)
            utxo = PartialTxInput(prevout=prevout, is_coinbase_output=is_cb)
            utxo._trusted_address = address
            utxo._trusted_value_sats = value
            utxo.block_height = tx_height
            utxo.spent_height, utxo.spent_islock = \
                spent.get(prevout_str, (None, None))
            utxo.islock = islock
            utxo.ps_rounds = ps_rounds
            out[prevout] = utxo
        return out

    def get_addr_utxo(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        out = self.get_addr_outputs(address)
        for k, v in list(out.items()):
            if v.spent_height is not None:
                out.pop(k)
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([v for height, v, is_cb, islock in received.values()])

    @with_local_height_cached
    def get_addr_balance(self, address, *, excluded_coins: Set[str] = None,
                         min_rounds=None, ps_denoms=None) -> Tuple[int, int, int]:
        """Return the balance of a bitcoin address:
        confirmed and matured, unconfirmed, unmatured

        min_rounds parameter consider values < 0 same as None
        """
        if min_rounds is not None and min_rounds < 0:
            min_rounds = None
        if ps_denoms is None:
            ps_denoms = {}
        # cache is only used if there are no excluded_coins or min_rounds
        if not excluded_coins and min_rounds is None:
            cached_value = self._get_addr_balance_cache.get(address)
            if cached_value:
                return cached_value
        if excluded_coins is None:
            excluded_coins = set()
        assert isinstance(excluded_coins, set), f"excluded_coins should be set, not {type(excluded_coins)}"
        received, sent = self.get_addr_io(address)
        c = u = x = 0
        mempool_height = self.get_local_height() + 1  # height of next block
        for txo, (tx_height, v, is_cb, islock) in received.items():
            if min_rounds is not None and txo not in ps_denoms:
                continue
            if txo in excluded_coins:
                continue
            if is_cb and tx_height + COINBASE_MATURITY > mempool_height:
                x += v
            elif tx_height > 0 or islock:
                c += v
            else:
                u += v
            if txo in sent:
                sent_height, sent_islock = sent[txo]
                if sent_height > 0 or sent_islock:
                    c -= v
                else:
                    u -= v
        result = c, u, x
        # cache result.
        if not excluded_coins and min_rounds is None:
            # Cache needs to be invalidated if a transaction is added to/
            # removed from history; or on new blocks (maturity...);
            # or new islock
            self._get_addr_balance_cache[address] = result
        return result

    @with_local_height_cached
    def get_utxos(
            self,
            domain=None,
            *,
            excluded_addresses=None,
            mature_only: bool = False,
            confirmed_funding_only: bool = False,
            confirmed_spending_only: bool = False,
            nonlocal_only: bool = False,
            block_height: int = None,
            consider_islocks=False,
            include_ps=False,
            min_rounds=None,
            prevout_timestamp=False,
    ) -> Sequence[PartialTxInput]:
        if block_height is not None:
            # caller wants the UTXOs we had at a given height; check other parameters
            assert confirmed_funding_only
            assert confirmed_spending_only
            assert nonlocal_only
            assert not consider_islocks
        else:
            block_height = self.get_local_height()
        coins = []
        ps_ks_domain = self.psman.get_addresses()
        if domain is None:
            if include_ps:
                domain = self.get_addresses() + ps_ks_domain
            else:
                ps_addrs = self.db.get_ps_addresses(min_rounds=min_rounds)
                if min_rounds is not None:
                    domain = ps_addrs
                else:
                    domain = self.get_addresses() + ps_ks_domain
                    domain = set(domain) - ps_addrs
        domain = set(domain)
        if excluded_addresses:
            domain = set(domain) - set(excluded_addresses)
        mempool_height = block_height + 1  # height of next block
        for addr in domain:
            txos = self.get_addr_outputs(addr)
            for txo in txos.values():
                if txo.address in ps_ks_domain:
                    txo.is_ps_ks = True
                else:
                    txo.is_ps_ks = False
                if min_rounds is not None:
                    ps_rounds = txo.ps_rounds
                    if ps_rounds is None or ps_rounds < min_rounds:
                        continue
                if txo.spent_height is not None:
                    if not confirmed_spending_only:
                        continue
                    if confirmed_spending_only and 0 < txo.spent_height <= block_height:
                        continue
                if confirmed_funding_only and not (0 < txo.block_height <= block_height):
                    if not consider_islocks:
                        continue
                    elif not txo.islock:
                        continue
                if nonlocal_only and txo.block_height in (TX_HEIGHT_LOCAL, ):
                    continue
                if (mature_only and txo.is_coinbase_output()
                        and txo.block_height + COINBASE_MATURITY > mempool_height):
                    continue
                if prevout_timestamp:
                    txid = txo.prevout.txid.hex()
                    tx_mined_status = self.get_tx_height(txid)
                    if tx_mined_status.conf > 0:
                        txo.prevout_timestamp = tx_mined_status.timestamp
                coins.append(txo)
                continue
        return coins

    def get_balance(self, domain=None, *, excluded_addresses: Set[str] = None,
                    excluded_coins: Set[str] = None,
                    include_ps=True, min_rounds=None) -> Tuple[int, int, int]:
        '''min_rounds parameter consider values < 0 same as None'''
        ps_denoms = {}
        if min_rounds is not None:
            if min_rounds < 0:
                min_rounds = None
            else:
                ps_denoms = self.db.get_ps_denoms(min_rounds=min_rounds)
        if domain is None:
            if include_ps:
                domain = self.get_addresses() + self.psman.get_addresses()
            else:
                if min_rounds is not None:
                    domain = [ps_denom[0] for ps_denom in ps_denoms.values()]
                else:
                    ps_addrs = self.db.get_ps_addresses()
                    domain = set(self.get_addresses() +
                                 self.psman.get_addresses()) - ps_addrs
        if excluded_addresses is None:
            excluded_addresses = set()
        assert isinstance(excluded_addresses, set), f"excluded_addresses should be set, not {type(excluded_addresses)}"
        domain = set(domain) - excluded_addresses
        cc = uu = xx = 0
        for addr in domain:
            c, u, x = self.get_addr_balance(addr,
                                            excluded_coins=excluded_coins,
                                            min_rounds=min_rounds,
                                            ps_denoms=ps_denoms)
            cc += c
            uu += u
            xx += x
        return cc, uu, xx

    def is_used(self, address: str) -> bool:
        return self.get_address_history_len(address) != 0

    def is_empty(self, address: str) -> bool:
        c, u, x = self.get_addr_balance(address)
        return c+u+x == 0

    def synchronize(self):
        pass
