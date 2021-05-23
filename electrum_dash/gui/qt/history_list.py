#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

import os
import sys
import time
import datetime
from datetime import date
from functools import partial
from typing import TYPE_CHECKING, Tuple, Dict
import threading
from enum import IntEnum
from decimal import Decimal

from PyQt5.QtGui import QMouseEvent, QFont, QBrush, QColor
from PyQt5.QtCore import (Qt, QPersistentModelIndex, QModelIndex,
                          QAbstractItemModel, QVariant, QItemSelectionModel,
                          QDate, QPoint, QItemSelection, pyqtSignal)
from PyQt5.QtWidgets import (QMenu, QHeaderView, QLabel, QMessageBox,
                             QPushButton, QComboBox, QVBoxLayout, QCalendarWidget,
                             QGridLayout)

from electrum_dash.gui import messages
from electrum_dash.address_synchronizer import TX_HEIGHT_LOCAL
from electrum_dash.dash_tx import PSTxTypes, SPEC_TX_NAMES
from electrum_dash.i18n import _
from electrum_dash.util import (block_explorer_URL, profiler, TxMinedInfo,
                                timestamp_to_datetime, FILE_OWNER_MODE,
                                Satoshis, format_time)
from electrum_dash.logging import get_logger, Logger

from .util import (read_QIcon, MONOSPACE_FONT, Buttons, CancelButton, OkButton,
                   filename_field, MyTreeView, AcceptFileDragDrop, WindowModalDialog,
                   CloseButton, webopen, WWLabel, GetDataThread)

if TYPE_CHECKING:
    from electrum_dash.wallet import Abstract_Wallet
    from .main_window import ElectrumWindow


_logger = get_logger(__name__)


try:
    from electrum_dash.plot import plot_history, NothingToPlotException
except:
    _logger.info("could not import electrum_dash.plot. This feature needs matplotlib to be installed.")
    plot_history = None

# note: this list needs to be kept in sync with another in kivy
TX_ICONS = [
    "unconfirmed.png",
    "warning.png",
    "offline_tx.png",
    "offline_tx.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "instantsend_locked.png",
    "confirmed.png",
]


class HistoryColumns(IntEnum):
    TX_GROUP = 0
    STATUS = 1
    DIP2 = 2
    DESCRIPTION = 3
    AMOUNT = 4
    BALANCE = 5
    FIAT_VALUE = 6
    FIAT_ACQ_PRICE = 7
    FIAT_CAP_GAINS = 8
    TXID = 9


def get_item_key(tx_item):
    return tx_item.get('txid')


class HistoryModel(QAbstractItemModel, Logger):

    data_ready = pyqtSignal()

    def __init__(self, parent):
        QAbstractItemModel.__init__(self, parent)
        Logger.__init__(self)
        self.parent = parent
        self.view = None  # type: HistoryList
        self.transactions = dict()
        self.tx_tree = list()
        self.expanded_groups = set()
        self.tx_status_cache = {}  # type: Dict[str, Tuple[int, str]]
        self.group_ps = self.parent.wallet.psman.group_history
        # read tx group control icons
        self.tx_group_expand_icn = read_QIcon('tx_group_expand.png')
        self.tx_group_collapse_icn = read_QIcon('tx_group_collapse.png')
        # setup bg thread to get updated data
        self.data_ready.connect(self.on_get_data, Qt.QueuedConnection)
        self.get_data_thread = GetDataThread(self, self.get_history_data,
                                             self.data_ready, self)
        self.get_data_thread.data_call_args = (self.group_ps, )
        self.get_data_thread.start()

        # sort keys methods for columns
        self.SORT_KEYS = {
            HistoryColumns.TX_GROUP: self.sort_ix,
            HistoryColumns.STATUS: self.sort_status,
            HistoryColumns.DIP2: self.sort_dip2,
            HistoryColumns.DESCRIPTION: self.sort_label,
            HistoryColumns.AMOUNT: self.sort_coin_value,
            HistoryColumns.BALANCE: self.sort_running_coin_balance,
            HistoryColumns.FIAT_VALUE: self.sort_fiat_value,
            HistoryColumns.FIAT_ACQ_PRICE: self.sort_fiat_acq_price,
            HistoryColumns.FIAT_CAP_GAINS: self.sort_fiat_cap_gains,
            HistoryColumns.TXID: self.sort_txid,
        }

    def set_view(self, history_list: 'HistoryList'):
        # FIXME HistoryModel and HistoryList mutually depend on each other.
        # After constructing both, this method needs to be called.
        self.view = history_list  # type: HistoryList
        self.set_visibility_of_columns()

    def columnCount(self, parent: QModelIndex):
        return len(HistoryColumns)

    def rowCount(self, parent: QModelIndex):
        if not parent.isValid():  # parent is root
            return len(self.tx_tree)

        if not self.group_ps:
            return 0

        parent_tx_item = parent.internalPointer()
        parent_idx_row = parent_tx_item['idx_row']
        return len(self.tx_tree[parent_idx_row][1])

    def index(self, row: int, column: int, parent: QModelIndex):
        if not parent.isValid():  # parent is root
            if len(self.tx_tree) <= row:
                return QModelIndex()
            return self.createIndex(row, column, self.tx_tree[row][0])

        parent_tx_item = parent.internalPointer()
        parent_idx_row = parent_tx_item['idx_row']
        children = self.tx_tree[parent_idx_row][1]
        tx_item = children[row]
        return self.createIndex(row, column, tx_item)

    def index_from_txid(self, txid):
        tx_item = self.transactions.get(txid)
        if not tx_item:
            return QModelIndex()

        idx_row = tx_item['idx_row']
        if not self.group_ps:
            return self.index(idx_row, 0, QModelIndex())

        idx_parent_row = tx_item['idx_parent_row']
        if idx_parent_row is None:
            return self.index(idx_row, 0, QModelIndex())
        else:
            paranet_idx = self.index(idx_parent_row, 0, QModelIndex())
            return self.index(idx_row, 0, paranet_idx)

    def parent(self, index: QModelIndex):
        if not index.isValid():  # root
            return QModelIndex()

        if not self.group_ps:
            return QModelIndex()

        parent_tx_item = index.internalPointer()
        idx_parent_row = parent_tx_item['idx_parent_row']
        if idx_parent_row is None:
            return QModelIndex()
        else:
            parent_tx_item = self.tx_tree[idx_parent_row][0]
            return self.createIndex(idx_parent_row, 0, parent_tx_item)

    def hasChildren(self, parent: QModelIndex):
        if not parent.isValid():  # parent is root
            return True

        if not self.group_ps:
            return False

        parent_tx_item = parent.internalPointer()
        idx_parent_row = parent_tx_item['idx_parent_row']
        if idx_parent_row is None:
            idx_row = parent_tx_item['idx_row']
            children = self.tx_tree[idx_row][1]
            return len(children) > 0
        else:
            return False

    def sort(self, col, order):
        if self.tx_tree:
            self.process_changes(self.sorted(self.tx_tree, col, order))

    def sort_ix(self, x, child=False):
        if child:
            return x['ix']
        else:
            return x[0]['ix']

    def sort_status(self, x, child=False):
        if child:
            return x['ix']
        else:
            return x[0]['ix']

    def sort_dip2(self, x, child=False):
        if child:
            return x['tx_type']
        else:
            group_tx_type = x[0].get('group_tx_type')
            if group_tx_type:
                return group_tx_type
            return x[0]['tx_type']

    def sort_label(self, x, child=False):
        if child:
            return x['label']
        else:
            group_label = x[0].get('group_label')
            if group_label:
                return group_label
            return x[0]['label']

    def sort_coin_value(self, x, child=False):
        if child:
            return x['value'].value
        else:
            group_value = x[0].get('group_value')
            if group_value:
                return group_value.value
            return x[0]['value'].value

    def sort_running_coin_balance(self, x, child=False):
        if child:
            return x['balance'].value
        else:
            return x[0]['balance'].value

    def sort_fiat_value(self, x, child=False):
        if child:
            return x['fiat_value'].value
        else:
            return x[0]['fiat_value'].value

    def sort_fiat_acq_price(self, x, child=False):
        if child:
            return x['acquisition_price']
        else:
            return x[0]['acquisition_price']

    def sort_fiat_cap_gains(self, x, child=False):
        if child:
            return x['capital_gain']
        else:
            return x[0]['capital_gain']

    def sort_txid(self, x, child=False):
        if child:
            return x['txid']
        else:
            return x[0]['txid']

    def sorted(self, tx_tree, col, order):
        key = self.SORT_KEYS[col]
        if self.group_ps:
            tx_tree = sorted(tx_tree, key=key, reverse=order)
            for i in range(len(tx_tree)):
                children = tx_tree[i][1]
                if children:
                    ch_key = partial(key, child=True)
                    tx_tree[i][1] = sorted(children, key=ch_key, reverse=order)
            return tx_tree
        else:
            return sorted(tx_tree, key=key, reverse=order)

    def data(self, index: QModelIndex, role: Qt.ItemDataRole) -> QVariant:
        assert index.isValid()
        col = index.column()
        tx_item = index.internalPointer()
        tx_hash = tx_item['txid']
        conf = tx_item['confirmations']
        islock = tx_item['islock']
        is_parent = ('group_label' in tx_item)
        if is_parent and tx_hash in self.expanded_groups:
            expanded = True
        else:
            expanded = False

        if not is_parent:
            tx_group_icon = None
        elif not expanded:
            tx_group_icon = self.tx_group_expand_icn
        else:
            tx_group_icon = self.tx_group_collapse_icn
        try:
            status, status_str = self.tx_status_cache[tx_hash]
        except KeyError:
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            status, status_str = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info, islock)

        if role not in (Qt.DisplayRole, Qt.EditRole):
            if col == HistoryColumns.TX_GROUP and role == Qt.DecorationRole:
                if tx_group_icon:
                    return QVariant(tx_group_icon)
            if col == HistoryColumns.STATUS and role == Qt.DecorationRole:
                return QVariant(read_QIcon(TX_ICONS[status]))
            elif col == HistoryColumns.STATUS and role == Qt.ToolTipRole:
                if tx_item['height'] == TX_HEIGHT_LOCAL:
                    msg = _("This transaction is only available on your local machine.\n"
                            "The currently connected server does not know about it.\n"
                            "You can either broadcast it now, or simply remove it.")
                    return QVariant(msg)
                c = str(conf) + _(' confirmation' + ('s' if conf != 1 else ''))
                if conf < 6 and islock:
                    res = 'InstantSend, %s' % c
                else:
                    res = c
                return QVariant(res)
            elif col not in [HistoryColumns.DESCRIPTION,
                             HistoryColumns.DIP2] and role == Qt.TextAlignmentRole:
                return QVariant(int(Qt.AlignRight | Qt.AlignVCenter))
            elif col != HistoryColumns.DESCRIPTION and role == Qt.FontRole:
                monospace_font = QFont(MONOSPACE_FONT)
                return QVariant(monospace_font)
            #elif col == HistoryColumns.DESCRIPTION and role == Qt.DecorationRole \
            #        and self.parent.wallet.invoices.paid.get(tx_hash):
            #    return QVariant(read_QIcon("seal"))
            elif col == HistoryColumns.DIP2 and role == Qt.ForegroundRole:
                dip2_brush = QBrush(QColor("#1c75bc"))
                return QVariant(dip2_brush)
            elif (col in (HistoryColumns.DESCRIPTION,
                          HistoryColumns.AMOUNT)
                    and role == Qt.ForegroundRole):
                if is_parent and not expanded:
                    value = tx_item['group_value'].value
                else:
                    value = tx_item['value'].value
                if value < 0:
                    red_brush = QBrush(QColor("#BC1E1E"))
                    return QVariant(red_brush)
            elif col == HistoryColumns.FIAT_VALUE and role == Qt.ForegroundRole \
                    and not tx_item.get('fiat_default') and tx_item.get('fiat_value') is not None:
                blue_brush = QBrush(QColor("#1E1EFF"))
                return QVariant(blue_brush)
            return QVariant()
        if col == HistoryColumns.STATUS:
            return QVariant(status_str)
        elif col == HistoryColumns.DIP2:
            if is_parent and not expanded:
                return QVariant(tx_item.get('group_tx_type', ''))
            else:
                return QVariant(tx_item.get('tx_type', ''))
        elif col == HistoryColumns.DESCRIPTION:
            if is_parent and not expanded:
                return QVariant(tx_item['group_label'])
            else:
                return QVariant(tx_item['label'])
        elif col == HistoryColumns.AMOUNT:
            if is_parent and not expanded:
                value = tx_item['group_value'].value
            else:
                value = tx_item['value'].value
            v_str = self.parent.format_amount(value, is_diff=True, whitespaces=True)
            return QVariant(v_str)
        elif col == HistoryColumns.BALANCE:
            if is_parent and not expanded:
                balance = tx_item['group_balance'].value
            else:
                balance = tx_item['balance'].value
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            return QVariant(balance_str)
        elif col == HistoryColumns.FIAT_VALUE and 'fiat_value' in tx_item:
            if is_parent and not expanded:
                return
            value_str = self.parent.fx.format_fiat(tx_item['fiat_value'].value)
            return QVariant(value_str)
        elif col == HistoryColumns.FIAT_ACQ_PRICE and \
                tx_item['value'].value < 0 and 'acquisition_price' in tx_item:
            if is_parent and not expanded:
                return
            # fixme: should use is_mine
            acq = tx_item['acquisition_price'].value
            return QVariant(self.parent.fx.format_fiat(acq))
        elif col == HistoryColumns.FIAT_CAP_GAINS and 'capital_gain' in tx_item:
            if is_parent and not expanded:
                return
            cg = tx_item['capital_gain'].value
            return QVariant(self.parent.fx.format_fiat(cg))
        elif col == HistoryColumns.TXID:
            return QVariant(tx_hash)
        return QVariant()

    def update_label(self, idx, tx_item):
        tx_item['label'] = self.parent.wallet.get_label_for_txid(get_item_key(tx_item))
        self.dataChanged.emit(idx, idx, [Qt.DisplayRole])

    def get_domain(self):
        '''Overridden in address_dialog.py'''
        return (self.parent.wallet.get_addresses() +
                self.parent.wallet.psman.get_addresses())

    @profiler
    def process_history(self, r, group_ps):
        row = 0
        child_row = 0
        children = []
        transactions = []
        tx_tree = []
        for i, tx_item in enumerate(r['transactions'][::-1]):
            tx_item['ix'] = i
            group_data = tx_item.pop('group_data')
            group_txid = tx_item['group_txid']
            if not group_ps:
                tx_item['idx_parent_row'] = None
                tx_item['idx_row'] = row
                row += 1
                tx_tree.append([tx_item, []])
            elif group_data:
                group_value, group_balance, group_txids = group_data
                group_tx_type = SPEC_TX_NAMES[PSTxTypes.PS_MIXING_TXS]
                group_len = len(group_txids)
                group_label = _('Group of {} Txs').format(group_len)
                tx_item['group_value'] = group_value
                tx_item['group_balance'] = group_balance
                tx_item['group_tx_type'] = group_tx_type
                tx_item['group_label'] = group_label
                tx_item['idx_parent_row'] = None
                tx_item['idx_row'] = row
                row += 1
                child_row = 0
                children = []
                tx_tree.append([tx_item, children])
            elif group_txid:
                tx_item['idx_parent_row'] = row - 1
                tx_item['idx_row'] = child_row
                child_row += 1
                children.append(tx_item)
            else:
                tx_item['idx_parent_row'] = None
                tx_item['idx_row'] = row
                row += 1
                child_row = 0
                children = []
                tx_tree.append([tx_item, []])
            transactions.append(tx_item)
        r['transactions'] = transactions
        r['tx_tree'] = tx_tree

    @profiler
    def process_changes(self, tx_tree, group_ps=None):
        selected = self.view.selectionModel().selectedRows()
        selected_txid = None
        if selected:
            idx = selected[0]
            if idx.isValid():
                tx_item = idx.internalPointer()
                if tx_item:
                    selected_txid = tx_item['txid']

        if self.group_ps:
            for i, (tx_item, children) in enumerate(self.tx_tree):
                if children:
                    parent_idx = self.index(i, 0, QModelIndex())
                    self.beginRemoveRows(parent_idx, 0, len(children)-1)
                    for c_tx_item in children:
                        child_txid = c_tx_item['txid']
                        del self.transactions[child_txid]
                    self.tx_tree[i] = [tx_item, []]
                    self.endRemoveRows()
        if self.tx_tree:
            self.beginRemoveRows(QModelIndex(), 0, len(self.tx_tree)-1)
            self.transactions.clear()
            self.tx_tree.clear()
            self.endRemoveRows()

        if group_ps is not None:
            self.group_ps = group_ps

        if self.group_ps:
            old_expanded_groups = self.expanded_groups
            self.expanded_groups = set()
            for i, (tx_item, children) in enumerate(tx_tree):
                self.beginInsertRows(QModelIndex(), i, i)
                txid = tx_item['txid']
                tx_item['idx_row'] = i
                self.tx_tree.append([tx_item, []])
                self.transactions[txid] = tx_item
                self.endInsertRows()
                if children:
                    children_txids = []
                    parent_idx = self.index(i, 0, QModelIndex())
                    self.beginInsertRows(parent_idx, 0, len(children)-1)
                    for ch_i, ch_tx_item in enumerate(children):
                        ch_tx_item['idx_row'] = ch_i
                        ch_tx_item['idx_parent_row'] = i
                        ch_txid = ch_tx_item['txid']
                        self.transactions[ch_txid] = ch_tx_item
                        children_txids.append(ch_txid)
                    self.tx_tree[i] = [tx_item, children]
                    self.endInsertRows()
                    for expanded_txid in old_expanded_groups:
                        if (expanded_txid == txid
                                or expanded_txid in children_txids):
                            self.expanded_groups.add(txid)
                            self.view.expand(parent_idx)
        else:
            self.expanded_groups = set()
            self.beginInsertRows(QModelIndex(), 0, len(tx_tree)-1)
            for item in tx_tree:
                tx_item = item[0]
                txid = tx_item['txid']
                self.tx_tree.append([tx_item, []])
                self.transactions[txid] = tx_item
            self.endInsertRows()

        if selected_txid:
            sel_model = self.view.selectionModel()
            SEL_CUR_ROW = (QItemSelectionModel.Rows |
                           QItemSelectionModel.SelectCurrent)
            idx = self.index_from_txid(selected_txid)
            if idx.isValid():
                selection = QItemSelection(idx, idx)
                sel_model.select(selection, SEL_CUR_ROW)

    @profiler
    def refresh(self, reason: str):
        self.logger.info(f"refreshing... reason: {reason}")
        assert self.parent.gui_thread == threading.current_thread(), 'must be called from GUI thread'
        assert self.view, 'view not set'
        # Comment out due to unstable works of maybe_defer_update
        #if self.view.maybe_defer_update():
        #    return
        group_ps = self.parent.wallet.psman.group_history
        self.set_visibility_of_columns(group_ps)
        self.get_data_thread.data_call_args = (group_ps, )
        self.get_data_thread.need_update.set()

    def on_get_data(self):
        self._refresh(self.get_data_thread.res,
                      self.get_data_thread.data_call_args[0])

    def get_history_data(self, group_ps):
        fx = self.parent.fx
        if fx:
            fx.history_used_spot = False
        get_hist = self.parent.wallet.get_full_history
        txs = get_hist(fx, onchain_domain=self.get_domain(), group_ps=group_ps)
        r = {'transactions': list(txs.values())}
        self.process_history(r, group_ps)
        return r

    def _refresh(self, r, group_ps):
        tx_tree = r['tx_tree']
        if tx_tree == self.tx_tree:
            return
        col = self.view.header().sortIndicatorSection()
        order = self.view.header().sortIndicatorOrder()
        self.process_changes(self.sorted(tx_tree, col, order), group_ps)

        self.view.filter()
        # update time filter
        if not self.view.years and self.tx_tree:
            start_date = date.today()
            end_date = date.today()
            if len(self.tx_tree) > 0:
                start_tx_item = self.tx_tree[-1][0]
                start_date = start_tx_item.get('date') or start_date
                end_tx_item = self.tx_tree[0][0]
                end_date = end_tx_item.get('date') or end_date
            self.view.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
            self.view.period_combo.insertItems(1, self.view.years)
        # update tx_status_cache
        self.tx_status_cache.clear()
        for txid, tx_item in self.transactions.items():
            islock = tx_item['islock']
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            self.tx_status_cache[txid] = self.parent.wallet.get_tx_status(txid, tx_mined_info, islock)

    def set_visibility_of_columns(self, group_ps=None):
        def set_visible(col: int, b: bool):
            self.view.showColumn(col) if b else self.view.hideColumn(col)
        # txid
        set_visible(HistoryColumns.TXID, False)
        # fiat
        history = self.parent.fx.show_history()
        cap_gains = self.parent.fx.get_history_capital_gains_config()
        set_visible(HistoryColumns.FIAT_VALUE, history)
        set_visible(HistoryColumns.FIAT_ACQ_PRICE, history and cap_gains)
        set_visible(HistoryColumns.FIAT_CAP_GAINS, history and cap_gains)
        def_dip2 = not self.parent.wallet.psman.unsupported
        show_dip2 = self.view.config.get('show_dip2_tx_type', def_dip2)
        set_visible(HistoryColumns.DIP2, show_dip2)
        if group_ps is None:
            group_ps = self.group_ps
        set_visible(HistoryColumns.TX_GROUP, group_ps)

    def update_fiat(self, idx, tx_item):
        txid = tx_item['txid']
        fee = tx_item.get('fee')
        value = tx_item['value'].value
        fiat_fields = self.parent.wallet.get_tx_item_fiat(
            tx_hash=txid, amount_sat=value, fx=self.parent.fx,
            tx_fee=fee.value if fee else None)
        tx_item.update(fiat_fields)
        self.dataChanged.emit(idx, idx, [Qt.DisplayRole, Qt.ForegroundRole])

    def update_tx_mined_status(self, tx_hash: str, tx_mined_info: TxMinedInfo):
        idx = self.index_from_txid(tx_hash)
        if not idx.isValid():
            return
        tx_item = idx.internalPointer()
        if not tx_item:
            return
        islock = tx_item['islock']
        self.tx_status_cache[tx_hash] = \
            self.parent.wallet.get_tx_status(tx_hash, tx_mined_info, islock)
        tx_item.update({
            'confirmations':  tx_mined_info.conf,
            'timestamp':      tx_mined_info.timestamp,
            'txpos_in_block': tx_mined_info.txpos,
            'date':           timestamp_to_datetime(tx_mined_info.timestamp),
        })
        idx_last = idx.sibling(idx.row(), HistoryColumns.TXID)
        self.dataChanged.emit(idx, idx_last)

    def on_fee_histogram(self):
        for tx_hash, tx_item in list(self.transactions.items()):
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            if tx_mined_info.conf > 0:
                # note: we could actually break here if we wanted
                # to rely on the order of txns in self.transactions
                continue
            self.update_tx_mined_status(tx_hash, tx_mined_info)

    def headerData(self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole):
        assert orientation == Qt.Horizontal
        if role != Qt.DisplayRole:
            return None
        fx = self.parent.fx
        fiat_title = 'n/a fiat value'
        fiat_acq_title = 'n/a fiat acquisition price'
        fiat_cg_title = 'n/a fiat capital gains'
        if fx and fx.show_history():
            fiat_title = '%s '%fx.ccy + _('Value')
            fiat_acq_title = '%s '%fx.ccy + _('Acquisition price')
            fiat_cg_title = '%s '%fx.ccy + _('Capital Gains')
        return {
            HistoryColumns.TX_GROUP: '',
            HistoryColumns.STATUS: _('Date'),
            HistoryColumns.DIP2: _('Type'),
            HistoryColumns.DESCRIPTION: _('Description'),
            HistoryColumns.AMOUNT: _('Amount'),
            HistoryColumns.BALANCE: _('Balance'),
            HistoryColumns.FIAT_VALUE: fiat_title,
            HistoryColumns.FIAT_ACQ_PRICE: fiat_acq_title,
            HistoryColumns.FIAT_CAP_GAINS: fiat_cg_title,
            HistoryColumns.TXID: 'TXID',
        }[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags # type: Qt.ItemFlag
        if idx.column() in self.view.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | int(extra_flags)

    @staticmethod
    def tx_mined_info_from_tx_item(tx_item):
        tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                    conf=tx_item['confirmations'],
                                    timestamp=tx_item['timestamp'])
        return tx_mined_info


class HistoryList(MyTreeView, AcceptFileDragDrop):
    filter_columns = [HistoryColumns.STATUS,
                      HistoryColumns.DIP2,
                      HistoryColumns.DESCRIPTION,
                      HistoryColumns.AMOUNT,
                      HistoryColumns.TXID]

    def __init__(self, parent, model: HistoryModel):
        super().__init__(parent, self.create_menu, stretch_column=HistoryColumns.DESCRIPTION)
        self.config = parent.config
        self.hm = model
        self.setModel(model)
        AcceptFileDragDrop.__init__(self, ".txn")
        self.setSortingEnabled(True)
        self.start_date = None
        self.end_date = None
        self.years = []
        self.create_toolbar_buttons()
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.sortByColumn(HistoryColumns.STATUS, Qt.AscendingOrder)
        self.editable_columns |= {HistoryColumns.FIAT_VALUE}

        self.header().setStretchLastSection(False)
        self.header().setMinimumSectionSize(32)
        for col in HistoryColumns:
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def on_combo(self, x):
        s = self.period_combo.itemText(x)
        x = s == _('Custom')
        self.start_button.setEnabled(x)
        self.end_button.setEnabled(x)
        if s == _('All'):
            self.start_date = None
            self.end_date = None
            self.start_button.setText("-")
            self.end_button.setText("-")
        else:
            try:
                year = int(s)
            except:
                return
            self.start_date = datetime.datetime(year, 1, 1)
            self.end_date = datetime.datetime(year+1, 1, 1)
            self.start_button.setText(_('From') + ' ' + self.format_date(self.start_date))
            self.end_button.setText(_('To') + ' ' + self.format_date(self.end_date))
        self.hide_rows()

    def create_toolbar_buttons(self):
        self.period_combo = QComboBox()
        self.start_button = QPushButton('-')
        self.start_button.pressed.connect(self.select_start_date)
        self.start_button.setEnabled(False)
        self.end_button = QPushButton('-')
        self.end_button.pressed.connect(self.select_end_date)
        self.end_button.setEnabled(False)
        self.period_combo.addItems([_('All'), _('Custom')])
        self.period_combo.activated.connect(self.on_combo)

    def get_toolbar_buttons(self):
        return self.period_combo, self.start_button, self.end_button

    def on_hide_toolbar(self):
        self.start_date = None
        self.end_date = None
        self.hide_rows()

    def save_toolbar_state(self, state, config):
        config.set_key('show_toolbar_history', state)

    def select_start_date(self):
        self.start_date = self.select_date(self.start_button)
        self.hide_rows()

    def select_end_date(self):
        self.end_date = self.select_date(self.end_button)
        self.hide_rows()

    def select_date(self, button):
        d = WindowModalDialog(self, _("Select date"))
        d.setMinimumSize(600, 150)
        d.date = None
        vbox = QVBoxLayout()
        def on_date(date):
            d.date = date
        cal = QCalendarWidget()
        cal.setGridVisible(True)
        cal.clicked[QDate].connect(on_date)
        vbox.addWidget(cal)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        d.setLayout(vbox)
        if d.exec_():
            if d.date is None:
                return None
            date = d.date.toPyDate()
            button.setText(self.format_date(date))
            return datetime.datetime(date.year, date.month, date.day)

    def show_summary(self):
        fx = self.parent.fx
        show_fiat = fx and fx.is_enabled() and fx.get_history_config()
        if not show_fiat:
            self.parent.show_message(_("Enable fiat exchange rate with history."))
            return
        h = self.parent.wallet.get_detailed_history(
            from_timestamp = time.mktime(self.start_date.timetuple()) if self.start_date else None,
            to_timestamp = time.mktime(self.end_date.timetuple()) if self.end_date else None,
            fx=fx)
        summary = h['summary']
        if not summary:
            self.parent.show_message(_("Nothing to summarize."))
            return
        start = summary['begin']
        end = summary['end']
        flow = summary['flow']
        start_date = start.get('date')
        end_date = end.get('date')
        format_amount = lambda x: self.parent.format_amount(x.value) + ' ' + self.parent.base_unit()
        format_fiat = lambda x: str(x) + ' ' + self.parent.fx.ccy

        d = WindowModalDialog(self, _("Summary"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        msg = messages.to_rtf(messages.MSG_CAPITAL_GAINS)
        vbox.addWidget(WWLabel(msg))
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Begin")), 0, 1)
        grid.addWidget(QLabel(_("End")), 0, 2)
        #
        grid.addWidget(QLabel(_("Date")), 1, 0)
        grid.addWidget(QLabel(self.format_date(start_date)), 1, 1)
        grid.addWidget(QLabel(self.format_date(end_date)), 1, 2)
        #
        grid.addWidget(QLabel(_("Xazab balance")), 2, 0)
        grid.addWidget(QLabel(format_amount(start['BTC_balance'])), 2, 1)
        grid.addWidget(QLabel(format_amount(end['BTC_balance'])), 2, 2)
        #
        grid.addWidget(QLabel(_("Xazab Fiat price")), 3, 0)
        grid.addWidget(QLabel(format_fiat(start.get('BTC_fiat_price'))), 3, 1)
        grid.addWidget(QLabel(format_fiat(end.get('BTC_fiat_price'))), 3, 2)
        #
        grid.addWidget(QLabel(_("Fiat balance")), 4, 0)
        grid.addWidget(QLabel(format_fiat(start.get('fiat_balance'))), 4, 1)
        grid.addWidget(QLabel(format_fiat(end.get('fiat_balance'))), 4, 2)
        #
        grid.addWidget(QLabel(_("Acquisition price")), 5, 0)
        grid.addWidget(QLabel(format_fiat(start.get('acquisition_price', ''))), 5, 1)
        grid.addWidget(QLabel(format_fiat(end.get('acquisition_price', ''))), 5, 2)
        #
        grid.addWidget(QLabel(_("Unrealized capital gains")), 6, 0)
        grid.addWidget(QLabel(format_fiat(start.get('unrealized_gains', ''))), 6, 1)
        grid.addWidget(QLabel(format_fiat(end.get('unrealized_gains', ''))), 6, 2)
        #
        grid2 = QGridLayout()
        grid2.addWidget(QLabel(_("Xazab incoming")), 0, 0)
        grid2.addWidget(QLabel(format_amount(flow['BTC_incoming'])), 0, 1)
        grid2.addWidget(QLabel(_("Fiat incoming")), 1, 0)
        grid2.addWidget(QLabel(format_fiat(flow.get('fiat_incoming'))), 1, 1)
        grid2.addWidget(QLabel(_("Xazab outgoing")), 2, 0)
        grid2.addWidget(QLabel(format_amount(flow['BTC_outgoing'])), 2, 1)
        grid2.addWidget(QLabel(_("Fiat outgoing")), 3, 0)
        grid2.addWidget(QLabel(format_fiat(flow.get('fiat_outgoing'))), 3, 1)
        #
        grid2.addWidget(QLabel(_("Realized capital gains")), 4, 0)
        grid2.addWidget(QLabel(format_fiat(flow.get('realized_capital_gains'))), 4, 1)
        vbox.addLayout(grid)
        vbox.addWidget(QLabel(_('Cash flow')))
        vbox.addLayout(grid2)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    def plot_history_dialog(self):
        if plot_history is None:
            self.parent.show_message(
                _("Can't plot history.") + '\n' +
                _("Perhaps some dependencies are missing...") + " (matplotlib?)")
            return
        try:
            res = []
            for tx_item, children in self.hm.tx_tree[::-1]:
                if children:
                    res.extend(children[::-1])
                res.append(tx_item)
            plt = plot_history(res)
            plt.show()
        except NothingToPlotException as e:
            self.parent.show_message(str(e))

    def on_edited(self, index, user_role, text):
        if not index.isValid():
            return

        column = index.column()
        tx_item = index.internalPointer()
        key = get_item_key(tx_item)
        if column == HistoryColumns.DESCRIPTION:
            if self.wallet.set_label(key, text): #changed
                self.hm.update_label(index, tx_item)
                self.parent.update_completions()
        elif column == HistoryColumns.FIAT_VALUE:
            self.wallet.set_fiat_value(key, self.parent.fx.ccy, text,
                                       self.parent.fx, tx_item['value'].value)
            value = tx_item['value'].value
            if value is not None:
                self.hm.update_fiat(index, tx_item)
        else:
            assert False

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        idx = self.indexAt(event.pos())
        if not idx.isValid():
            return
        tx_item = idx.internalPointer()
        if idx.column() == HistoryColumns.TX_GROUP:
            event.ignore()
            return
        is_parent = ('group_label' in tx_item)
        txid = tx_item['txid']
        if self.hm.flags(idx) & Qt.ItemIsEditable:
            if is_parent and txid not in self.hm.expanded_groups:
                self.show_transaction(txid)
            else:
                super().mouseDoubleClickEvent(event)
        else:
            self.show_transaction(txid)

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            idx = self.indexAt(event.pos())
            if idx.isValid() and idx.column() == HistoryColumns.TX_GROUP:
                tx_item = idx.internalPointer()
                txid = tx_item.get('txid')
                is_parent = ('group_label' in tx_item)
                if is_parent:
                    if txid not in self.hm.expanded_groups:
                        self.expand_tx_group(txid)
                    else:
                        self.collapse_tx_group(txid)
                    event.ignore()
                    return
                group_txid = tx_item.get('group_txid')
                if group_txid:
                    self.collapse_tx_group(group_txid)
                    event.ignore()
                    return
        super().mousePressEvent(event)

    def show_transaction(self, tx_hash):
        tx = self.wallet.db.get_transaction(tx_hash)
        if not tx:
            return
        label = self.wallet.get_label_for_txid(tx_hash) or None # prefer 'None' if not defined (force tx dialog to hide Description field if missing)
        self.parent.show_transaction(tx, tx_desc=label)

    def add_copy_menu(self, menu, idx):
        cc = menu.addMenu(_("Copy"))
        for column in HistoryColumns:
            if column == HistoryColumns.TX_GROUP:
                continue
            if self.isColumnHidden(column):
                continue
            column_title = self.hm.headerData(column, Qt.Horizontal, Qt.DisplayRole)
            idx2 = idx.sibling(idx.row(), column)
            tx_item = self.hm.data(idx2, Qt.DisplayRole)
            if not tx_item:
                continue
            column_data = (tx_item.value() or '').strip()
            cc.addAction(
                column_title,
                lambda text=column_data, title=column_title:
                self.place_text_on_clipboard(text, title=title))
        return cc

    def create_menu(self, position: QPoint):
        idx: QModelIndex = self.indexAt(position)
        if not idx.isValid():
            # can happen e.g. before list is populated for the first time
            return
        tx_item = idx.internalPointer()
        tx_hash = tx_item['txid']
        group_txid = tx_item.get('group_txid')
        is_parent = ('group_label' in tx_item)
        if is_parent and tx_hash in self.hm.expanded_groups:
            expanded = True
        else:
            expanded = False
        tx = self.wallet.db.get_transaction(tx_hash)
        if not tx:
            return
        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        tx_details = self.wallet.get_tx_info(tx)
        menu = QMenu()
        if group_txid:
            collapse_m = lambda: self.collapse_tx_group(group_txid)
            menu.addAction(_("Collapse Tx Group"), collapse_m)
        if is_parent:
            if expanded:
                collapse_m = lambda: self.collapse_tx_group(tx_hash)
                menu.addAction(_("Collapse Tx Group"), collapse_m)
            else:
                expand_m = lambda: self.expand_tx_group(tx_hash)
                menu.addAction(_("Expand Tx Group"), expand_m)
        if tx_details.can_remove and (not is_parent or expanded):
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))
        cc = self.add_copy_menu(menu, idx)
        cc.addAction(_("Transaction ID"), lambda: self.place_text_on_clipboard(tx_hash, title="TXID"))
        for c in self.editable_columns:
            if is_parent and not expanded: continue
            if self.isColumnHidden(c): continue
            label = self.hm.headerData(c, Qt.Horizontal, Qt.DisplayRole)
            # TODO use siblingAtColumn when min Qt version is >=5.11
            persistent = QPersistentModelIndex(idx.sibling(idx.row(), c))
            menu.addAction(_("Edit {}").format(label), lambda p=persistent: self.edit(QModelIndex(p)))
        menu.addAction(_("View Transaction"),
                       lambda: self.show_transaction(tx_hash))
        invoices = self.wallet.get_relevant_invoices_for_tx(tx)
        if len(invoices) == 1:
            menu.addAction(_("View invoice"), lambda inv=invoices[0]: self.parent.show_onchain_invoice(inv))
        elif len(invoices) > 1:
            menu_invs = menu.addMenu(_("Related invoices"))
            for inv in invoices:
                menu_invs.addAction(_("View invoice"), lambda inv=inv: self.parent.show_onchain_invoice(inv))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webopen(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def expand_tx_group(self, txid):
        if txid not in self.hm.expanded_groups:
            idx = self.hm.index_from_txid(txid)
            if idx.isValid():
                idx_last = idx.sibling(idx.row(), HistoryColumns.TXID)
                self.hm.expanded_groups.add(txid)
                self.expand(idx)
                self.hm.dataChanged.emit(idx, idx_last)

    def collapse_tx_group(self, txid):
        if txid in self.hm.expanded_groups:
            idx = self.hm.index_from_txid(txid)
            if idx.isValid():
                idx_last = idx.sibling(idx.row(), HistoryColumns.TXID)
                self.hm.expanded_groups.remove(txid)
                self.collapse(idx)
                self.hm.dataChanged.emit(idx, idx_last)

    def remove_local_tx(self, tx_hash):
        num_child_txs = len(self.wallet.get_depending_transactions(tx_hash))
        question = _("Are you sure you want to remove this transaction?")
        if num_child_txs > 0:
            question = (_("Are you sure you want to remove this transaction and {} child transactions?")
                        .format(num_child_txs))
        if not self.parent.question(msg=question,
                                    title=_("Please confirm")):
            return
        self.wallet.remove_transaction(tx_hash)
        self.wallet.save_db()
        # need to update at least: history_list, utxo_list, address_list
        self.parent.need_update.set()

    def onFileAdded(self, fn):
        try:
            with open(fn) as f:
                tx = self.parent.tx_from_text(f.read())
        except IOError as e:
            self.parent.show_error(e)
            return
        if not tx:
            return
        self.parent.save_transaction_into_wallet(tx)

    def export_history_dialog(self):
        d = WindowModalDialog(self, _('Export History'))
        d.setMinimumSize(400, 200)
        vbox = QVBoxLayout(d)
        defaultname = os.path.expanduser('~/electrum-dash-history.csv')
        select_msg = _('Select file to export your wallet transactions to')
        hbox, filename_e, csv_button = filename_field(self, self.config, defaultname, select_msg)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        hbox = Buttons(CancelButton(d), OkButton(d, _('Export')))
        vbox.addLayout(hbox)
        #run_hook('export_history_dialog', self, hbox)
        self.update()
        if not d.exec_():
            return
        filename = filename_e.text()
        if not filename:
            return
        try:
            self.do_export_history(filename, csv_button.isChecked())
        except (IOError, os.error) as reason:
            export_error_label = _("Xazab Electrum was unable to produce a transaction export.")
            self.parent.show_critical(export_error_label + "\n" + str(reason), title=_("Unable to export history"))
            return
        self.parent.show_message(_("Your wallet history has been successfully exported."))

    def do_export_history(self, file_name, is_csv):
        hist = self.wallet.get_detailed_history(fx=self.parent.fx)
        txns = hist['transactions']
        lines = []
        if is_csv:
            for item in txns:
                lines.append([item['txid'],
                              item.get('label', ''),
                              item['confirmations'],
                              item['bc_value'],
                              item.get('fiat_value', ''),
                              item.get('fee', ''),
                              item.get('fiat_fee', ''),
                              item['date']])
        with open(file_name, "w+", encoding='utf-8') as f:
            if is_csv:
                import csv
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash",
                                      "label",
                                      "confirmations",
                                      "value",
                                      "fiat_value",
                                      "fee",
                                      "fiat_fee",
                                      "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                from electrum_dash.util import json_encode
                f.write(json_encode(txns))
        os.chmod(file_name, FILE_OWNER_MODE)

    def hide_rows(self):
        for i, (tx_item, children) in enumerate(self.hm.tx_tree):
            if children:
                left_children = len(children)
                parent_idx = self.hm.createIndex(i, 0, tx_item)
                for ch_tx_item in children:
                    if self.hide_tx_item(ch_tx_item, parent_idx):
                        left_children -= 1
                not_hide = (left_children > 0)
                self.hide_tx_item(tx_item, QModelIndex(), not_hide=not_hide)
            else:
                self.hide_tx_item(tx_item, QModelIndex())

    def hide_tx_item(self, tx_item, parent_idx, not_hide=False):
        idx = self.hm.index_from_txid(tx_item['txid'])
        if not idx.isValid():
            return True
        if not_hide:
            self.setRowHidden(idx.row(), parent_idx, False)
            return False
        should_hide = self.should_hide(tx_item)
        if not self.current_filter and should_hide is None:
            # no filters at all, neither date nor search
            self.setRowHidden(idx.row(), parent_idx, False)
            return False
        for column in self.filter_columns:
            txt_idx = idx.sibling(idx.row(), column)
            txt = self.hm.data(txt_idx, Qt.DisplayRole).value().lower()
            if self.current_filter in txt:
                # the filter matched, but the date filter might apply
                self.setRowHidden(idx.row(), parent_idx, bool(should_hide))
                return bool(should_hide)
        else:
            # we did not find the filter in any columns, hide the item
            self.setRowHidden(idx.row(), parent_idx, True)
            return True

    def should_hide(self, tx_item):
        if self.start_date and self.end_date:
            date = tx_item['date']
            if date:
                in_interval = self.start_date <= date <= self.end_date
                if not in_interval:
                    return True
            return False

    def get_text_and_userrole_from_coordinate(self, row, col, idx):
        if not idx.isValid():
            return None, None
        tx_item = idx.internalPointer()
        return self.hm.data(idx, Qt.DisplayRole).value(), get_item_key(tx_item)
