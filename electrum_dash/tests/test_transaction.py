from typing import NamedTuple, Union

from electrum_dash import transaction, bitcoin
from electrum_dash.transaction import (convert_raw_tx_to_hex, tx_from_any, Transaction,
                                       PartialTransaction, TxOutpoint, PartialTxInput,
                                       PartialTxOutput)
from electrum_dash.util import bh2u, bfh
from electrum_dash.bitcoin import (deserialize_privkey, opcodes,
                                   construct_script)
from electrum_dash.ecc import ECPrivkey

from . import ElectrumTestCase, TestCaseForTestnet

signed_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"

signed_blob_signatures = ['3046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d98501',]

class TestBCDataStream(ElectrumTestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEqual(bh2u(s.input),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEqual(s.read_compact_size(), v)

        with self.assertRaises(transaction.SerializationError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEqual(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_bytes(1)
        s.write(b'foobar')
        self.assertEqual(s.read_bytes(3), b'foo')
        self.assertEqual(s.read_bytes(2), b'ba')
        with self.assertRaises(transaction.SerializationError):
            s.read_bytes(4)
        self.assertEqual(s.read_bytes(0), b'')
        self.assertEqual(s.read_bytes(1), b'r')
        self.assertEqual(s.read_bytes(0), b'')

    def test_bool(self):
        s = transaction.BCDataStream()
        s.write(b'f\x00\x00b')
        self.assertTrue(s.read_boolean())
        self.assertFalse(s.read_boolean())
        self.assertFalse(s.read_boolean())
        self.assertTrue(s.read_boolean())
        s.write_boolean(True)
        s.write_boolean(False)
        self.assertEqual(b'\x01\x00', s.read_bytes(2))
        self.assertFalse(s.can_read_more())


class TestTransaction(ElectrumTestCase):

    def test_tx_update_signatures(self):
        tx = tx_from_any("cHNidP8BAFUBAAAAASpcmpT83pj1WBzQAWLGChOTbOt1OJ6mW/OGM7Qk60AxAAAAAAD/////AUBCDwAAAAAAGXapFCMKw3g0BzpCFG8R74QUrpKf6q/DiKwAAAAAAAAA")
        tx.inputs()[0].script_type = 'p2pkh'
        tx.inputs()[0].pubkeys = [bfh('02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6')]
        tx.inputs()[0].num_sig = 1
        tx.update_signatures(signed_blob_signatures)
        self.assertEqual(tx.serialize(), signed_blob)

    def test_tx_setting_locktime_invalidates_ser_cache(self):
        tx = tx_from_any("cHNidP8BAHcCAAAAAWyCzM99I/2SycDZnPPayWZS+ZozSpSrJLBX4FyCL49fAAAAAAD9////AqCGAQAAAAAAGXapFAxqYK54d8H5ibtBejF2OcSVH+EdiKyMtg0AAAAAABl2qRT0diWoHck1vHoqzAb0wHM3lyaxqIis+m0cAAABAL8CAAAAAYiMLT9lasuCkktD+2wEV1saKygxkn/ADsANcDCOzva0AAAAAGpHMEQCIHmgjA6hnSE0uVVV2TaoECm+8lgsBBZ/5njPUSRnfkvlAiBTaJmXZV4OlDFv7kV41LYbo9EuSxcue27lUywe5IzMhgEhAjE9gvq9Vd1AIrfvDHDNSzGRcaH1wvRbD3Yo3zGr9Oez/v///wGHPQ8AAAAAABl2qRR3pG7tV/kiyeMvMTa1XuSA8BNvd4isirIYAAEHakcwRAIgENgIS8aA0P62J/6/Ckff0MIj3N/0BX7rthg/kOhCCLoCIFs0n4a6X0nYFHPh1s+PNEk1RUFt1hFJn9mdZaD/mxwzASECMT2C+r1V3UAit+8McM1LMZFxofXC9FsPdijfMav057MBCAEAACICAsoTK7g0VRAI452fKagixHpIJbRhm74S3qtRydyY44JADJxdDAAAAAAAAQAAAAAiAgL11TJWAb6PAWSoqtvVweiqhqrrWHUxIB3WHdzO78cL/QycXQwAAQAAAAAAAAAA")
        self.assertEqual("3e2e70b3e49c70b79784145ba83cbd0d699e6c92ebcc646329151614251351a0", tx.txid())
        tx.locktime = 111222333
        self.assertEqual("2adbecb393e4de6c6b9b404f27319a85c594e84f3d8cf2e1c138ce900c2feff1", tx.txid())

    def test_tx_setting_version_invalidates_ser_cache(self):
        tx = tx_from_any("cHNidP8BAHcCAAAAAWyCzM99I/2SycDZnPPayWZS+ZozSpSrJLBX4FyCL49fAAAAAAD9////AqCGAQAAAAAAGXapFAxqYK54d8H5ibtBejF2OcSVH+EdiKyMtg0AAAAAABl2qRT0diWoHck1vHoqzAb0wHM3lyaxqIis+m0cAAABAL8CAAAAAYiMLT9lasuCkktD+2wEV1saKygxkn/ADsANcDCOzva0AAAAAGpHMEQCIHmgjA6hnSE0uVVV2TaoECm+8lgsBBZ/5njPUSRnfkvlAiBTaJmXZV4OlDFv7kV41LYbo9EuSxcue27lUywe5IzMhgEhAjE9gvq9Vd1AIrfvDHDNSzGRcaH1wvRbD3Yo3zGr9Oez/v///wGHPQ8AAAAAABl2qRR3pG7tV/kiyeMvMTa1XuSA8BNvd4isirIYAAEHakcwRAIgENgIS8aA0P62J/6/Ckff0MIj3N/0BX7rthg/kOhCCLoCIFs0n4a6X0nYFHPh1s+PNEk1RUFt1hFJn9mdZaD/mxwzASECMT2C+r1V3UAit+8McM1LMZFxofXC9FsPdijfMav057MBCAEAACICAsoTK7g0VRAI452fKagixHpIJbRhm74S3qtRydyY44JADJxdDAAAAAAAAQAAAAAiAgL11TJWAb6PAWSoqtvVweiqhqrrWHUxIB3WHdzO78cL/QycXQwAAQAAAAAAAAAA")
        self.assertEqual("3e2e70b3e49c70b79784145ba83cbd0d699e6c92ebcc646329151614251351a0", tx.txid())
        tx.version = 555
        self.assertEqual("1aa9f34130ee64f5d9e6bbe4ff7a5ffad708f10bb689895a188392fe5aeb7083", tx.txid())

    def test_tx_deserialize_for_signed_network_tx(self):
        tx = transaction.Transaction(signed_blob)
        tx.deserialize()
        self.assertEqual(1, tx.version)
        self.assertEqual(0, tx.locktime)
        self.assertEqual(1, len(tx.inputs()))
        self.assertEqual(4294967295, tx.inputs()[0].nsequence)
        self.assertEqual(bfh('493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'),
                         tx.inputs()[0].script_sig)
        self.assertEqual('3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a:0', tx.inputs()[0].prevout.to_str())
        self.assertEqual(1, len(tx.outputs()))
        self.assertEqual(bfh('76a914230ac37834073a42146f11ef8414ae929feaafc388ac'), tx.outputs()[0].scriptpubkey)
        self.assertEqual('Xdt8NqE5wSX9ytfP958t4tKdXoZDo6Bm6T', tx.outputs()[0].address)
        self.assertEqual(1000000, tx.outputs()[0].value)
        self.assertEqual(0, tx.tx_type)
        self.assertEqual(b'', tx.extra_payload)

        self.assertEqual(tx.serialize(), signed_blob)

    def test_estimated_tx_size(self):
        tx = transaction.Transaction(signed_blob)

        self.assertEqual(tx.estimated_total_size(), 193)
        self.assertEqual(tx.estimated_base_size(), 193)
        self.assertEqual(tx.estimated_weight(), 772)
        self.assertEqual(tx.estimated_size(), 193)

    def test_estimated_output_size(self):
        estimated_output_size = transaction.Transaction.estimated_output_size_for_address
        self.assertEqual(estimated_output_size('XeNTG4aihv1ru8xmaoiQnToSi8hLiTTNbh'), 34)
        self.assertEqual(estimated_output_size('7WHUEVtMDLeereT5r4ZoNKjr3MXr4gqfon'), 32)

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")

    def test_convert_raw_tx_to_hex(self):
        # raw hex
        self.assertEqual('020000000001012005273af813ba23b0c205e4b145e525c280dd876e061f35bff7db9b2e0043640100000000fdffffff02d885010000000000160014e73f444b8767c84afb46ef4125d8b81d2542a53d00e1f5050000000017a914052ed032f5c74a636ed5059611bb90012d40316c870247304402200c628917673d75f05db893cc377b0a69127f75e10949b35da52aa1b77a14c350022055187adf9a668fdf45fc09002726ba7160e713ed79dddcd20171308273f1a2f1012103cb3e00561c3439ccbacc033a72e0513bcfabff8826de0bc651d661991ade6171049e1600',
                         convert_raw_tx_to_hex('020000000001012005273af813ba23b0c205e4b145e525c280dd876e061f35bff7db9b2e0043640100000000fdffffff02d885010000000000160014e73f444b8767c84afb46ef4125d8b81d2542a53d00e1f5050000000017a914052ed032f5c74a636ed5059611bb90012d40316c870247304402200c628917673d75f05db893cc377b0a69127f75e10949b35da52aa1b77a14c350022055187adf9a668fdf45fc09002726ba7160e713ed79dddcd20171308273f1a2f1012103cb3e00561c3439ccbacc033a72e0513bcfabff8826de0bc651d661991ade6171049e1600'))
        # base43
        self.assertEqual('020000000001012005273af813ba23b0c205e4b145e525c280dd876e061f35bff7db9b2e0043640100000000fdffffff02d885010000000000160014e73f444b8767c84afb46ef4125d8b81d2542a53d00e1f5050000000017a914052ed032f5c74a636ed5059611bb90012d40316c870247304402200c628917673d75f05db893cc377b0a69127f75e10949b35da52aa1b77a14c350022055187adf9a668fdf45fc09002726ba7160e713ed79dddcd20171308273f1a2f1012103cb3e00561c3439ccbacc033a72e0513bcfabff8826de0bc651d661991ade6171049e1600',
                         convert_raw_tx_to_hex('64XF-8+PM6*4IYN-QWW$B2QLNW+:C8-$I$-+T:L.6DKXTSWSFFONDP1J/MOS3SPK0-SYVW38U9.3+A1/*2HTHQTJGP79LVEK-IITQJ1H.C/X$NSOV$8DWR6JAFWXD*LX4-EN0.BDOF+PPYPH16$NM1H.-MAA$V1SCP0Q.6Y5FR822S6K-.5K5F.Z4Q:0SDRG-4GEBLAO4W9Z*H-$1-KDYAFOGF675W0:CK5M1LT92IG:3X60P3GKPM:X2$SP5A7*LT9$-TTEG0/DRZYV$7B4ADL9CVS5O7YG.J64HLZ24MVKO/-GV:V.T/L$D3VQ:MR8--44HK8W'))

    def test_get_address_from_output_script(self):
        # the inverse of this test is in test_bitcoin: test_address_to_script
        addr_from_script = lambda script: transaction.get_address_from_output_script(bfh(script))

        # almost but not quite
        self.assertEqual(None, addr_from_script('0013751e76e8199196d454941c45d1b3a323f1433b'))

        # base58 p2pkh
        self.assertEqual('XeNTG4aihv1ru8xmaoiQnToSi8hLiTTNbh', addr_from_script('76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac'))
        self.assertEqual('XkvgWFLxVmDaVkUF8bFE2QXP4f5C2KKWEg', addr_from_script('76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac'))
        # almost but not quite
        self.assertEqual(None, addr_from_script('76a9130000000000000000000000000000000000000088ac'))

        # base58 p2sh
        self.assertEqual('7WHUEVtMDLeereT5r4ZoNKjr3MXr4gqfon', addr_from_script('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'))
        self.assertEqual('7phNpVKta6kkbP24HfvvQVeHEmgBQYiJCB', addr_from_script('a914f47c8954e421031ad04ecd8e7752c9479206b9d387'))
        # almost but not quite
        self.assertEqual(None, addr_from_script('a912f47c8954e421031ad04ecd8e7752c947920687'))

        # p2pk
        self.assertEqual(None, addr_from_script('210289e14468d94537493c62e2168318b568912dec0fb95609afd56f2527c2751c8bac'))
        self.assertEqual(None, addr_from_script('41045485b0b076848af1209e788c893522a90f3df77c1abac2ca545846a725e6c3da1f7743f55a1bc3b5f0c7e0ee4459954ec0307022742d60032b13432953eb7120ac'))
        # almost but not quite
        self.assertEqual(None, addr_from_script('200289e14468d94537493c62e2168318b568912dec0fb95609afd56f2527c2751cac'))
        self.assertEqual(None, addr_from_script('210589e14468d94537493c62e2168318b568912dec0fb95609afd56f2527c2751c8bac'))

    def test_tx_serialize_methods_for_psbt(self):
        raw_hex = "70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c0000000000"
        raw_base64 = "cHNidP8BAHcCAAAAAWyCzM99I/2SycDZnPPayWZS+ZozSpSrJLBX4FyCL49fAAAAAAD9////AqCGAQAAAAAAGXapFAxqYK54d8H5ibtBejF2OcSVH+EdiKyMtg0AAAAAABl2qRT0diWoHck1vHoqzAb0wHM3lyaxqIis+m0cAAAAAAA="
        partial_tx = tx_from_any(raw_hex)
        self.assertEqual(PartialTransaction, type(partial_tx))
        self.assertEqual(raw_base64,
                         partial_tx.serialize())
        self.assertEqual(raw_hex,
                         partial_tx.serialize_as_bytes().hex())
        self.assertEqual(raw_base64,
                         partial_tx._serialize_as_base64())

    def test_tx_serialize_methods_for_network_tx(self):
        raw_hex = "02000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f000000006a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00"
        tx = tx_from_any(raw_hex)
        self.assertEqual(Transaction, type(tx))
        self.assertEqual(raw_hex,
                         tx.serialize())
        self.assertEqual(raw_hex,
                         tx.serialize_as_bytes().hex())

    def test_tx_serialize_methods_for_psbt_that_is_ready_to_be_finalized(self):
        raw_hex_psbt = "70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00000100bf0200000001888c2d3f656acb82924b43fb6c04575b1a2b2831927fc00ec00d70308ecef6b4000000006a473044022079a08c0ea19d2134b95555d936a81029bef2582c04167fe678cf5124677e4be5022053689997655e0e94316fee4578d4b61ba3d12e4b172e7b6ee5532c1ee48ccc86012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3feffffff01873d0f00000000001976a91477a46eed57f922c9e32f3136b55ee480f0136f7788ac8ab2180001076a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b30108010000220202ca132bb834551008e39d9f29a822c47a4825b4619bbe12deab51c9dc98e382400c9c5d0c00000000000100000000220202f5d5325601be8f0164a8aadbd5c1e8aa86aaeb587531201dd61ddcceefc70bfd0c9c5d0c00010000000000000000"
        raw_hex_network_tx = "02000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f000000006a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00"
        partial_tx = tx_from_any(raw_hex_psbt)
        self.assertEqual(PartialTransaction, type(partial_tx))
        self.assertEqual(raw_hex_network_tx,
                         partial_tx.serialize())
        self.assertEqual(raw_hex_network_tx,
                         partial_tx.serialize_as_bytes().hex())
        # note: the diff between the following, and raw_hex_psbt, is that we added
        #       an extra FINAL_SCRIPTWITNESS field in finalize_psbt()
        self.assertEqual("70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00000100bf0200000001888c2d3f656acb82924b43fb6c04575b1a2b2831927fc00ec00d70308ecef6b4000000006a473044022079a08c0ea19d2134b95555d936a81029bef2582c04167fe678cf5124677e4be5022053689997655e0e94316fee4578d4b61ba3d12e4b172e7b6ee5532c1ee48ccc86012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3feffffff01873d0f00000000001976a91477a46eed57f922c9e32f3136b55ee480f0136f7788ac8ab2180001076a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b30108010000220202ca132bb834551008e39d9f29a822c47a4825b4619bbe12deab51c9dc98e382400c9c5d0c00000000000100000000220202f5d5325601be8f0164a8aadbd5c1e8aa86aaeb587531201dd61ddcceefc70bfd0c9c5d0c00010000000000000000",
                         partial_tx.serialize_as_bytes(force_psbt=True).hex())

    def test_tx_from_any(self):
        class RawTx(NamedTuple):
            data: Union[str, bytes]
            is_whitespace_allowed: bool = True
        raw_tx_map = {
            "network_tx_hex_str": RawTx("02000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f000000006a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00"),
            "network_tx_hex_bytes": RawTx(b"02000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f000000006a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00"),
            "network_tx_base43_str": RawTx("51P$627A:E*C:XKA8G94LS5EXZOZX0Q51549JSDVLFONBFP3YF2OE:1K9H95V-:5HQLPW19B8+TJ6$ZXJNDTK92LWR-/YJ+XHZ5.OBHQ2-08QB$VMNDKUIDKK25B8:M8.8:B$ILDVL$8IX4:5UP0*G:N+PN$X93ID./ZFFPZ2*.U$/I7Z24*S-JLY-DS$7$9STL9T:KGXC$M$J18-J:K2.AAHYPRBKLYT2LYTRED:2E-MH-NTUSJX6I+J15:WGH$H8.7SMSO.QQ8UA3387ER92ZQLYRVYJ33MKRY+7C-HGUJX.-47Y*7H7L0T3WO3J0D3UMTYUT.B*L"),
            "network_tx_base43_bytes": RawTx(b"51P$627A:E*C:XKA8G94LS5EXZOZX0Q51549JSDVLFONBFP3YF2OE:1K9H95V-:5HQLPW19B8+TJ6$ZXJNDTK92LWR-/YJ+XHZ5.OBHQ2-08QB$VMNDKUIDKK25B8:M8.8:B$ILDVL$8IX4:5UP0*G:N+PN$X93ID./ZFFPZ2*.U$/I7Z24*S-JLY-DS$7$9STL9T:KGXC$M$J18-J:K2.AAHYPRBKLYT2LYTRED:2E-MH-NTUSJX6I+J15:WGH$H8.7SMSO.QQ8UA3387ER92ZQLYRVYJ33MKRY+7C-HGUJX.-47Y*7H7L0T3WO3J0D3UMTYUT.B*L"),
            "network_tx_raw_bytes": RawTx(bytes.fromhex("02000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f000000006a473044022010d8084bc680d0feb627febf0a47dfd0c223dcdff4057eebb6183f90e84208ba02205b349f86ba5f49d81473e1d6cf8f34493545416dd611499fd99d65a0ff9b1c33012102313d82fabd55dd4022b7ef0c70cd4b319171a1f5c2f45b0f7628df31abf4e7b3fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c00"),
                                          is_whitespace_allowed=False),
            "psbt_hex_str": RawTx("70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c0000000000"),
            "psbt_hex_bytes": RawTx(b"70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c0000000000"),
            "psbt_base64_str": RawTx("cHNidP8BAHcCAAAAAWyCzM99I/2SycDZnPPayWZS+ZozSpSrJLBX4FyCL49fAAAAAAD9////AqCGAQAAAAAAGXapFAxqYK54d8H5ibtBejF2OcSVH+EdiKyMtg0AAAAAABl2qRT0diWoHck1vHoqzAb0wHM3lyaxqIis+m0cAAAAAAA="),
            "psbt_base64_bytes": RawTx(b"cHNidP8BAHcCAAAAAWyCzM99I/2SycDZnPPayWZS+ZozSpSrJLBX4FyCL49fAAAAAAD9////AqCGAQAAAAAAGXapFAxqYK54d8H5ibtBejF2OcSVH+EdiKyMtg0AAAAAABl2qRT0diWoHck1vHoqzAb0wHM3lyaxqIis+m0cAAAAAAA="),
            "psbt_base43_str": RawTx("VE:1Z.8T+8ZAN2SAQT$P:JB2V2QC7*A7S$6E0393P8:ZMZUF5/CX.E-JJ6I-ZZY4U72VRMBG8I2U/B7AM7VJ5JZ$DKJ$P-IB4C5-V8EUVA/4D.3+/2.O2.9GB$M1/G5H3$IL4/ZBBQUJTZMIN+T9FNE*S.8XZ2-NPQPQE48Z62*GRJS*DQ0DSH-DY+/8-GOLC"),
            "psbt_base43_bytes": RawTx(b'VE:1Z.8T+8ZAN2SAQT$P:JB2V2QC7*A7S$6E0393P8:ZMZUF5/CX.E-JJ6I-ZZY4U72VRMBG8I2U/B7AM7VJ5JZ$DKJ$P-IB4C5-V8EUVA/4D.3+/2.O2.9GB$M1/G5H3$IL4/ZBBQUJTZMIN+T9FNE*S.8XZ2-NPQPQE48Z62*GRJS*DQ0DSH-DY+/8-GOLC'),
            "psbt_raw_bytes": RawTx(bytes.fromhex("70736274ff01007702000000016c82cccf7d23fd92c9c0d99cf3dac96652f99a334a94ab24b057e05c822f8f5f0000000000fdffffff02a0860100000000001976a9140c6a60ae7877c1f989bb417a317639c4951fe11d88ac8cb60d00000000001976a914f47625a81dc935bc7a2acc06f4c073379726b1a888acfa6d1c0000000000"),
                                    is_whitespace_allowed=False),
        }
        whitespace_str = " \r\n  \n  "
        whitespace_bytes = b" \r\n  \n  "
        for case_name, raw_tx in raw_tx_map.items():
            for has_whitespaces in (False, True):
                with self.subTest(msg=case_name, has_whitespaces=has_whitespaces):
                    if not has_whitespaces:
                        data = raw_tx.data
                        tx_from_any(data)  # test if raises (should not)
                    else:
                        if isinstance(raw_tx.data, str):
                            data = whitespace_str + raw_tx.data + whitespace_str
                        else:
                            data = whitespace_bytes + raw_tx.data + whitespace_bytes
                        if raw_tx.is_whitespace_allowed:
                            tx_from_any(data)  # test if raises (should not)
                        else:
                            with self.assertRaises(transaction.SerializationError):
                                tx_from_any(data)  # test if raises (should)

#####

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

    def test_txid_coinbase_to_p2pk(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000'
        txid = 'dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_coinbase_to_p2pkh(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000'
        txid = '4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2pkh(self):
        raw_tx = '010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000'
        txid = '90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2sh(self):
        raw_tx = '0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000'
        txid = '172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2pkh(self):
        raw_tx = '0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000'
        txid = '24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2sh(self):
        raw_tx = '010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000'
        txid = '155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    # input: p2sh, not multisig
    def test_txid_regression_issue_3899(self):
        raw_tx = '0100000004328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c010000000b0009630330472d5fae685bffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c020000000b0009630359646d5fae6858ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c030000000b000963034bd4715fae6854ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c040000000b000963036de8705fae6860ffffffff0130750000000000001976a914b5abca61d20f9062fb1fdbb880d9d93bac36675188ac00000000'
        txid = 'f570d5d1e965ee61bcc7005f8fefb1d3abbed9d7ddbe035e2a68fa07e5fc4a0d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_negative_version_num(self):
        raw_tx = '01007b9a01ecf5e5c3bbf2cf1f71ecdc7f708b0b222432e914b394e24aad1494a42990ddfc000000008b483045022100852744642305a99ad74354e9495bf43a1f96ded470c256cd32e129290f1fa191022030c11d294af6a61b3da6ed2c0c296251d21d113cfd71ec11126517034b0dcb70014104a0fe6e4a600f859a0932f701d3af8e0ecd4be886d91045f06a5a6b931b95873aea1df61da281ba29cadb560dad4fc047cf47b4f7f2570da4c0b810b3dfa7e500ffffffff0240420f00000000001976a9147eeacb8a9265cd68c92806611f704fc55a21e1f588ac05f00d00000000001976a914eb3bd8ccd3ba6f1570f844b59ba3e0a667024a6a88acff7f0000'
        txid = '57d40e31e4ff032f452b3211d01a40c5e492410d512d339013aa69c48a271f99'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_regression_issue_4333(self):
        raw_tx = '0100000001a300499298b3f03200c05d1a15aa111a33c769aff6fb355c6bf52ebdb58ca37100000000171600756161616161616161616161616161616161616151fdffffff01c40900000000000017a914001975d5f07f3391674416c1fcd67fd511d257ff871bc71300'
        txid = '9b9f39e314662a7433aadaa5c94a2f1e24c7e7bf55fc9e1f83abd72be933eb95'
        self._run_naive_tests_on_tx(raw_tx, txid)

    # see https://bitcoin.stackexchange.com/questions/38006/txout-script-criteria-scriptpubkey-critieria
    def test_txid_invalid_op_return(self):
        raw_tx = '01000000019ac03d5ae6a875d970128ef9086cef276a1919684a6988023cc7254691d97e6d010000006b4830450221009d41dc793ba24e65f571473d40b299b6459087cea1509f0d381740b1ac863cb6022039c425906fcaf51b2b84d8092569fb3213de43abaff2180e2a799d4fcb4dd0aa012102d5ede09a8ae667d0f855ef90325e27f6ce35bbe60a1e6e87af7f5b3c652140fdffffffff080100000000000000010101000000000000000202010100000000000000014c0100000000000000034c02010100000000000000014d0100000000000000044dffff010100000000000000014e0100000000000000064effffffff0100000000'
        txid = 'ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767'
        self._run_naive_tests_on_tx(raw_tx, txid)


# these transactions are from Bitcoin Core unit tests --->
# https://github.com/bitcoin/bitcoin/blob/11376b5583a283772c82f6d32d0007cdbf5b8ef0/src/test/data/tx_valid.json

    def test_txid_bitcoin_core_0001(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = '23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0002(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a0048304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2bab01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'fcabc409d8e685da28536e1e5ccc91264d755cd4c57ed4cae3dbaa4d3b93e8ed'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0003(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a01ff47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'c9aa95f2c48175fdb70b34c23f1c3fc44f869b073a6f79b1343fbce30c3cb575'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0004(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000495147304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'da94fda32b55deb40c3ed92e135d69df7efc4ee6665e0beb07ef500f407c9fd2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0005(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000494f47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'f76f897b206e4f78d60fe40f2ccb542184cfadc34354d3bb9bdc30cc2f432b86'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0006(self):
        raw_tx = '01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d00000000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac00000000'
        txid = 'c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0007(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000'
        txid = 'e41ffe19dff3cbedb413a2ca3fbbcd05cb7fd7397ffa65052f8928aa9c700092'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0008(self):
        raw_tx = '01000000023d6cf972d4dff9c519eff407ea800361dd0a121de1da8b6f4138a2f25de864b4000000008a4730440220ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e022049cffa1cdc102a0b56e0e04913606c70af702a1149dc3b305ab9439288fee090014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff21ebc9ba20594737864352e95b727f1a565756f9d365083eb1a8596ec98c97b7010000008a4730440220503ff10e9f1e0de731407a4a245531c9ff17676eda461f8ceeb8c06049fa2c810220c008ac34694510298fa60b3f000df01caa244f165b727d4896eb84f81e46bcc4014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff01f0da5200000000001976a914857ccd42dded6df32949d4646dfa10a92458cfaa88ac00000000'
        txid = 'f7fdd091fa6d8f5e7a8c2458f5c38faffff2d3f1406b6e4fe2c99dcc0d2d1cbb'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0009(self):
        raw_tx = '01000000020002000000000000000000000000000000000000000000000000000000000000000000000151ffffffff0001000000000000000000000000000000000000000000000000000000000000000000006b483045022100c9cdd08798a28af9d1baf44a6c77bcc7e279f47dc487c8c899911bc48feaffcc0220503c5c50ae3998a733263c5c0f7061b483e2b56c4c41b456e7d2f5a78a74c077032102d5c25adb51b61339d2b05315791e21bbe80ea470a49db0135720983c905aace0ffffffff010000000000000000015100000000'
        txid = 'b56471690c3ff4f7946174e51df68b47455a0d29344c351377d712e6d00eabe5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0010(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000009085768617420697320ffffffff010000000000000000015100000000'
        txid = '99517e5b47533453cc7daa332180f578be68b80370ecfe84dbfff7f19d791da4'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0011(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006e493046022100c66c9cdf4c43609586d15424c54707156e316d88b0a1534c9e6b0d4f311406310221009c0fe51dbc9c4ab7cc25d3fdbeccf6679fe6827f08edf2b4a9f16ee3eb0e438a0123210338e8034509af564c62644c07691942e0c056752008a173c89f60ab2a88ac2ebfacffffffff010000000000000000015100000000'
        txid = 'ab097537b528871b9b64cb79a769ae13c3c3cd477cc9dddeebe657eabd7fdcea'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0012(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006e493046022100e1eadba00d9296c743cb6ecc703fd9ddc9b3cd12906176a226ae4c18d6b00796022100a71aef7d2874deff681ba6080f1b278bac7bb99c61b08a85f4311970ffe7f63f012321030c0588dc44d92bdcbf8e72093466766fdc265ead8db64517b0c542275b70fffbacffffffff0100064194d8b80600015100000000'
        txid = '8d268064359f04404d1a6a9cb059751f211e445b07396358aae358e7e600d7ec'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0013(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006d483045022027deccc14aa6668e78a8c9da3484fbcd4f9dcc9bb7d1b85146314b21b9ae4d86022100d0b43dece8cfb07348de0ca8bc5b86276fa88f7f2138381128b7c36ab2e42264012321029bb13463ddd5d2cc05da6e84e37536cb9525703cfd8f43afdb414988987a92f6acffffffff0200064194d8b8060001510000000000000000015100000000'
        txid = 'cd0b05966360f719847bc2af3225a18da2a41bb0e8e8c9e6b68df9c71fe2a2dc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0014(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff025151ffffffff010000000000000000015100000000'
        txid = '99d3825137602e577aeaf6a2e3c9620fd0e605323dc5265da4a570593be791d4'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0015(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6451515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000'
        txid = 'c0d67409923040cc766bbea12e4c9154393abef706db065ac2e07d91a9ba4f84'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0016(self):
        raw_tx = '010000000200010000000000000000000000000000000000000000000000000000000000000000000049483045022100d180fd2eb9140aeb4210c9204d3f358766eb53842b2a9473db687fa24b12a3cc022079781799cd4f038b85135bbe49ec2b57f306b2bb17101b17f71f000fcab2b6fb01ffffffff0002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000'
        txid = 'c610d85d3d5fdf5046be7f123db8a0890cee846ee58de8a44667cfd1ab6b8666'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0017(self):
        raw_tx = '01000000020001000000000000000000000000000000000000000000000000000000000000000000004948304502203a0f5f0e1f2bdbcd04db3061d18f3af70e07f4f467cbc1b8116f267025f5360b022100c792b6e215afc5afc721a351ec413e714305cb749aae3d7fee76621313418df101010000000002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000'
        txid = 'a647a7b3328d2c698bfa1ee2dd4e5e05a6cea972e764ccb9bd29ea43817ca64f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0018(self):
        raw_tx = '010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf63000000006a4730440220360d20baff382059040ba9be98947fd678fb08aab2bb0c172efa996fd8ece9b702201b4fb0de67f015c90e7ac8a193aeab486a1f587e0f54d0fb9552ef7f5ce6caec032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff7d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e804010000006b483045022100c714310be1e3a9ff1c5f7cacc65c2d8e781fc3a88ceb063c6153bf950650802102200b2d0979c76e12bb480da635f192cc8dc6f905380dd4ac1ff35a4f68f462fffd032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff3f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee010000006c493046022100b663499ef73273a3788dea342717c2640ac43c5a1cf862c9e09b206fcb3f6bb8022100b09972e75972d9148f2bdd462e5cb69b57c1214b88fc55ca638676c07cfc10d8032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff0380841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9cfdfb88ac80841e00000000001976a9149857cc07bed33a5cf12b9c5e0500b675d500c81188ace0fd1c00000000001976a91443c52850606c872403c0601e69fa34b26f62db4a88ac00000000'
        txid = 'afd9c17f8913577ec3509520bd6e5d63e9c0fd2a5f70c787993b097ba6ca9fae'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0019(self):
        raw_tx = '01000000012312503f2491a2a97fcd775f11e108a540a5528b5d4dee7a3c68ae4add01dab300000000fdfe0000483045022100f6649b0eddfdfd4ad55426663385090d51ee86c3481bdc6b0c18ea6c0ece2c0b0220561c315b07cffa6f7dd9df96dbae9200c2dee09bf93cc35ca05e6cdf613340aa0148304502207aacee820e08b0b174e248abd8d7a34ed63b5da3abedb99934df9fddd65c05c4022100dfe87896ab5ee3df476c2655f9fbe5bd089dccbef3e4ea05b5d121169fe7f5f4014c695221031d11db38972b712a9fe1fc023577c7ae3ddb4a3004187d41c45121eecfdbb5b7210207ec36911b6ad2382860d32989c7b8728e9489d7bbc94a6b5509ef0029be128821024ea9fac06f666a4adc3fc1357b7bec1fd0bdece2b9d08579226a8ebde53058e453aeffffffff0180380100000000001976a914c9b99cddf847d10685a4fabaa0baf505f7c3dfab88ac00000000'
        txid = 'f4b05f978689c89000f729cae187dcfbe64c9819af67a4f05c0b4d59e717d64d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0020(self):
        raw_tx = '0100000001f709fa82596e4f908ee331cb5e0ed46ab331d7dcfaf697fe95891e73dac4ebcb000000008c20ca42095840735e89283fec298e62ac2ddea9b5f34a8cbb7097ad965b87568100201b1b01dc829177da4a14551d2fc96a9db00c6501edfa12f22cd9cefd335c227f483045022100a9df60536df5733dd0de6bc921fab0b3eee6426501b43a228afa2c90072eb5ca02201c78b74266fac7d1db5deff080d8a403743203f109fbcabf6d5a760bf87386d20100ffffffff01c075790000000000232103611f9a45c18f28f06f19076ad571c344c82ce8fcfe34464cf8085217a2d294a6ac00000000'
        txid = 'cc60b1f899ec0a69b7c3f25ddf32c4524096a9c5b01cbd84c6d0312a0c478984'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0021(self):
        raw_tx = '01000000012c651178faca83be0b81c8c1375c4b0ad38d53c8fe1b1c4255f5e795c25792220000000049483045022100d6044562284ac76c985018fc4a90127847708c9edb280996c507b28babdc4b2a02203d74eca3f1a4d1eea7ff77b528fde6d5dc324ec2dbfdb964ba885f643b9704cd01ffffffff010100000000000000232102c2410f8891ae918cab4ffc4bb4a3b0881be67c7a1e7faa8b5acf9ab8932ec30cac00000000'
        txid = '1edc7f214659d52c731e2016d258701911bd62a0422f72f6c87a1bc8dd3f8667'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0022(self):
        raw_tx = '0100000001f725ea148d92096a79b1709611e06e94c63c4ef61cbae2d9b906388efd3ca99c000000000100ffffffff0101000000000000002321028a1d66975dbdf97897e3a4aef450ebeb5b5293e4a0b4a6d3a2daaa0b2b110e02ac00000000'
        txid = '018adb7133fde63add9149a2161802a1bcf4bdf12c39334e880c073480eda2ff'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0023(self):
        raw_tx = '0100000001be599efaa4148474053c2fa031c7262398913f1dc1d9ec201fd44078ed004e44000000004900473044022022b29706cb2ed9ef0cb3c97b72677ca2dfd7b4160f7b4beb3ba806aa856c401502202d1e52582412eba2ed474f1f437a427640306fd3838725fab173ade7fe4eae4a01ffffffff010100000000000000232103ac4bba7e7ca3e873eea49e08132ad30c7f03640b6539e9b59903cf14fd016bbbac00000000'
        txid = '1464caf48c708a6cc19a296944ded9bb7f719c9858986d2501cf35068b9ce5a2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0024(self):
        raw_tx = '010000000112b66d5e8c7d224059e946749508efea9d66bf8d0c83630f080cf30be8bb6ae100000000490047304402206ffe3f14caf38ad5c1544428e99da76ffa5455675ec8d9780fac215ca17953520220779502985e194d84baa36b9bd40a0dbd981163fa191eb884ae83fc5bd1c86b1101ffffffff010100000000000000232103905380c7013e36e6e19d305311c1b81fce6581f5ee1c86ef0627c68c9362fc9fac00000000'
        txid = '1fb73fbfc947d52f5d80ba23b67c06a232ad83fdd49d1c0a657602f03fbe8f7a'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0025(self):
        raw_tx = '0100000001b0ef70cc644e0d37407e387e73bfad598d852a5aa6d691d72b2913cebff4bceb000000004a00473044022068cd4851fc7f9a892ab910df7a24e616f293bcb5c5fbdfbc304a194b26b60fba022078e6da13d8cb881a22939b952c24f88b97afd06b4c47a47d7f804c9a352a6d6d0100ffffffff0101000000000000002321033bcaa0a602f0d44cc9d5637c6e515b0471db514c020883830b7cefd73af04194ac00000000'
        txid = '24cecfce0fa880b09c9b4a66c5134499d1b09c01cc5728cd182638bea070e6ab'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0026(self):
        raw_tx = '0100000001c188aa82f268fcf08ba18950f263654a3ea6931dabc8bf3ed1d4d42aaed74cba000000004b0000483045022100940378576e069aca261a6b26fb38344e4497ca6751bb10905c76bb689f4222b002204833806b014c26fd801727b792b1260003c55710f87c5adbd7a9cb57446dbc9801ffffffff0101000000000000002321037c615d761e71d38903609bf4f46847266edc2fb37532047d747ba47eaae5ffe1ac00000000'
        txid = '9eaa819e386d6a54256c9283da50c230f3d8cd5376d75c4dcc945afdeb157dd7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0027(self):
        raw_tx = '01000000012432b60dc72cebc1a27ce0969c0989c895bdd9e62e8234839117f8fc32d17fbc000000004a493046022100a576b52051962c25e642c0fd3d77ee6c92487048e5d90818bcf5b51abaccd7900221008204f8fb121be4ec3b24483b1f92d89b1b0548513a134e345c5442e86e8617a501ffffffff010000000000000000016a00000000'
        txid = '46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0028(self):
        raw_tx = '01000000014710b0e7cf9f8930de259bdc4b84aa5dfb9437b665a3e3a21ff26e0bf994e183000000004a493046022100a166121a61b4eeb19d8f922b978ff6ab58ead8a5a5552bf9be73dc9c156873ea02210092ad9bc43ee647da4f6652c320800debcf08ec20a094a0aaf085f63ecb37a17201ffffffff010000000000000000016a00000000'
        txid = '8d66836045db9f2d7b3a75212c5e6325f70603ee27c8333a3bce5bf670d9582e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0029(self):
        raw_tx = '01000000015ebaa001d8e4ec7a88703a3bcf69d98c874bca6299cca0f191512bf2a7826832000000004948304502203bf754d1c6732fbf87c5dcd81258aefd30f2060d7bd8ac4a5696f7927091dad1022100f5bcb726c4cf5ed0ed34cc13dadeedf628ae1045b7cb34421bc60b89f4cecae701ffffffff010000000000000000016a00000000'
        txid = 'aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0030(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a900000000924830450221009c0a27f886a1d8cb87f6f595fbc3163d28f7a81ec3c4b252ee7f3ac77fd13ffa02203caa8dfa09713c8c4d7ef575c75ed97812072405d932bd11e6a1593a98b679370148304502201e3861ef39a526406bad1e20ecad06be7375ad40ddb582c9be42d26c3a0d7b240221009d0a3985e96522e59635d19cc4448547477396ce0ef17a58e7d74c3ef464292301ffffffff010000000000000000016a00000000'
        txid = '6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0031(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0100ffffffff010000000000000000016a00000000'
        txid = '892464645599cc3c2d165adcc612e5f982a200dfaa3e11e9ce1d228027f46880'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0032(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510151ffffffff010000000000000000016a00000000'
        txid = '578db8c6c404fec22c4a8afeaf32df0e7b767c4dda3478e0471575846419e8fc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0033(self):
        raw_tx = '0100000001e0be9e32f1f89c3d916c4f21e55cdcd096741b895cc76ac353e6023a05f4f7cc00000000d86149304602210086e5f736a2c3622ebb62bd9d93d8e5d76508b98be922b97160edc3dcca6d8c47022100b23c312ac232a4473f19d2aeb95ab7bdf2b65518911a0d72d50e38b5dd31dc820121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac4730440220508fa761865c8abd81244a168392876ee1d94e8ed83897066b5e2df2400dad24022043f5ee7538e87e9c6aef7ef55133d3e51da7cc522830a9c4d736977a76ef755c0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = '974f5148a0946f9985e75a240bb24c573adbbdc25d61e7b016cdbb0a5355049f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0034(self):
        raw_tx = '01000000013c6f30f99a5161e75a2ce4bca488300ca0c6112bde67f0807fe983feeff0c91001000000e608646561646265656675ab61493046022100ce18d384221a731c993939015e3d1bcebafb16e8c0b5b5d14097ec8177ae6f28022100bcab227af90bab33c3fe0a9abfee03ba976ee25dc6ce542526e9b2e56e14b7f10121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac493046022100c3b93edcc0fd6250eb32f2dd8a0bba1754b0f6c3be8ed4100ed582f3db73eba2022100bf75b5bd2eff4d6bf2bda2e34a40fcc07d4aa3cf862ceaa77b47b81eff829f9a01ab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'b0097ec81df231893a212657bf5fe5a13b2bff8b28c0042aca6fc4159f79661b'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0035(self):
        raw_tx = '01000000016f3dbe2ca96fa217e94b1017860be49f20820dea5c91bdcb103b0049d5eb566000000000fd1d0147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac47304402203757e937ba807e4a5da8534c17f9d121176056406a6465054bdd260457515c1a02200f02eccf1bec0f3a0d65df37889143c2e88ab7acec61a7b6f5aa264139141a2b0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'feeba255656c80c14db595736c1c7955c8c0a497622ec96e3f2238fbdd43a7c9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0036(self):
        raw_tx = '01000000012139c555ccb81ee5b1e87477840991ef7b386bc3ab946b6b682a04a621006b5a01000000fdb40148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f2204148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390175ac4830450220646b72c35beeec51f4d5bc1cbae01863825750d7f490864af354e6ea4f625e9c022100f04b98432df3a9641719dbced53393022e7249fb59db993af1118539830aab870148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a580039017521038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'a0c984fc820e57ddba97f8098fa640c8a7eb3fe2f583923da886b7660f505e1e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0037(self):
        raw_tx = '0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000'
        txid = '5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0038(self):
        raw_tx = '0100000002dbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce000000006b4830450221009627444320dc5ef8d7f68f35010b4c050a6ed0d96b67a84db99fda9c9de58b1e02203e4b4aaa019e012e65d69b487fdf8719df72f488fa91506a80c49a33929f1fd50121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffffdbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce010000009300483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303ffffffff01a0860100000000001976a9149bc0bbdd3024da4d0c38ed1aecf5c68dd1d3fa1288ac00000000'
        txid = 'ded7ff51d89a4e1ec48162aee5a96447214d93dfb3837946af2301a28f65dbea'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0039(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = '3444be2e216abe77b46015e481d8cc21abd4c20446aabf49cd78141c9b9db87e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0040(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000ff64cd1d'
        txid = 'abd62b4627d8d9b2d95fcfd8c87e37d2790637ce47d28018e3aece63c1d62649'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0041(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000065cd1d'
        txid = '58b6de8413603b7f556270bf48caedcf17772e7105f5419f6a80be0df0b470da'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0042(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000ffffffff'
        txid = '5f99c0abf511294d76cbe144d86b77238a03e086974bc7a8ea0bdb2c681a0324'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0043(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000feffffff0100000000000000000000000000'
        txid = '25d35877eaba19497710666473c50d5527d38503e3521107a3fc532b74cd7453'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0044(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000feffffff'
        txid = '1b9aef851895b93c62c29fbd6ca4d45803f4007eff266e2f96ff11e9b6ef197b'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0045(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = '3444be2e216abe77b46015e481d8cc21abd4c20446aabf49cd78141c9b9db87e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0046(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000000251b1000000000100000000000000000001000000'
        txid = 'f53761038a728b1f17272539380d96e93f999218f8dcb04a8469b523445cd0fd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0047(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000030251b1000000000100000000000000000001000000'
        txid = 'd193f0f32fceaf07bb25c897c8f99ca6f69a52f6274ca64efc2a2e180cb97fc1'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0048(self):
        raw_tx = '010000000132211bdd0d568506804eef0d8cc3db68c3d766ab9306cdfcc0a9c89616c8dbb1000000006c493045022100c7bb0faea0522e74ff220c20c022d2cb6033f8d167fb89e75a50e237a35fd6d202203064713491b1f8ad5f79e623d0219ad32510bfaa1009ab30cbee77b59317d6e30001210237af13eb2d84e4545af287b919c2282019c9691cc509e78e196a9d8274ed1be0ffffffff0100000000000000001976a914f1b3ed2eda9a2ebe5a9374f692877cdf87c0f95b88ac00000000'
        txid = '50a1e0e6a134a564efa078e3bd088e7e8777c2c0aec10a752fd8706470103b89'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0049(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = 'e2207d1aaf6b74e5d98c2fa326d2dc803b56b30a3f90ce779fa5edb762f38755'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0050(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffff00000100000000000000000000000000'
        txid = 'f335864f7c12ec7946d2c123deb91eb978574b647af125a414262380c7fbd55c'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0051(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffbf7f0100000000000000000000000000'
        txid = 'd1edbcde44691e98a7b7f556bd04966091302e29ad9af3c2baac38233667e0d2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0052(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000040000100000000000000000000000000'
        txid = '3a13e1b6371c545147173cc4055f0ed73686a9f73f092352fb4b39ca27d360e6'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0053(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffff40000100000000000000000000000000'
        txid = 'bffda23e40766d292b0510a1b556453c558980c70c94ab158d8286b3413e220d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0054(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffff7f0100000000000000000000000000'
        txid = '01a86c65460325dc6699714d26df512a62a854a669f6ed2e6f369a238e048cfd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0055(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000000800100000000000000000000000000'
        txid = 'f6d2359c5de2d904e10517d23e7c8210cca71076071bbf46de9fbd5f6233dbf1'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0056(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000feffffff0100000000000000000000000000'
        txid = '19c2b7377229dae7aa3e50142a32fd37cef7171a01682f536e9ffa80c186f6c9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0057(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100000000000000000000000000'
        txid = 'c9dda3a24cc8a5acb153d1085ecd2fecf6f87083122f8cdecc515b1148d4c40d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0058(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffbf7f0100000000000000000000000000'
        txid = 'd1edbcde44691e98a7b7f556bd04966091302e29ad9af3c2baac38233667e0d2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0059(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffff7f0100000000000000000000000000'
        txid = '01a86c65460325dc6699714d26df512a62a854a669f6ed2e6f369a238e048cfd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0060(self):
        raw_tx = '02000000010001000000000000000000000000000000000000000000000000000000000000000000000251b2010000000100000000000000000000000000'
        txid = '4b5e0aae1251a9dc66b4d5f483f1879bf518ea5e1765abc5a9f2084b43ed1ea7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0061(self):
        raw_tx = '0200000001000100000000000000000000000000000000000000000000000000000000000000000000030251b2010000000100000000000000000000000000'
        txid = '5f16eb3ca4581e2dfb46a28140a4ee15f85e4e1c032947da8b93549b53c105f5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0080(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000015100000000'
        txid = '2b1e44fff489d09091e5e20f9a01bbc0e8d80f0662e629fd10709cdb4922a874'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0084(self):
        raw_tx = '01000000020001000000000000000000000000000000000000000000000000000000000000000000004847304402202a0b4b1294d70540235ae033d78e64b4897ec859c7b6f1b2b1d8a02e1d46006702201445e756d2254b0f1dfda9ab8e1e1bc26df9668077403204f32d16a49a36eb6983ffffffff00010000000000000000000000000000000000000000000000000000000000000100000049483045022100acb96cfdbda6dc94b489fd06f2d720983b5f350e31ba906cdbd800773e80b21c02200d74ea5bdf114212b4bbe9ed82c36d2e369e302dff57cb60d01c428f0bd3daab83ffffffff02e8030000000000000151e903000000000000015100000000'
        txid = '98229b70948f1c17851a541f1fe532bf02c408267fecf6d7e174c359ae870654'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0089(self):
        raw_tx = '010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f1581b0000b64830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0121037a3fb04bcdb09eba90f69961ba1692a3528e45e67c85b200df820212d7594d334aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01ffffffff0101000000000000000000000000'
        txid = '22d020638e3b7e1f2f9a63124ac76f5e333c74387862e3675f64b25e960d3641'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0091(self):
        raw_tx = '01000000019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a662896581b0000fd6f01004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c03959601522102cd74a2809ffeeed0092bc124fd79836706e41f048db3f6ae9df8708cefb83a1c2102e615999372426e46fd107b76eaf007156a507584aa2cc21de9eee3bdbd26d36c4c9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960175ffffffff0101000000000000000000000000'
        txid = '1aebf0c98f01381765a8c33d688f8903e4d01120589ac92b78f1185dc1f4119c'
        self._run_naive_tests_on_tx(raw_tx, txid)

# txns from Bitcoin Core ends <---


class TestTransactionTestnet(TestCaseForTestnet):

    def test_spending_op_cltv_p2sh(self):
        # from https://github.com/brianddk/reddit/blob/8ca383c9e00cb5a4c1201d1bab534d5886d3cb8f/python/elec-p2sh-hodl.py
        wif = 'cQNjiPwYKMBr2oB3bWzf3rgBsu198xb8Nxxe51k6D3zVTA98L25N'
        sats = 9999
        sats_less_fees = sats - 200
        locktime = 1602565200

        # Build the Transaction Input
        _, privkey, compressed = deserialize_privkey(wif)
        pubkey = ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        prevout = TxOutpoint(txid=bfh('6d500966f9e494b38a04545f0cea35fc7b3944e341a64b804fed71cdee11d434'), out_idx=1)
        txin = PartialTxInput(prevout=prevout)
        txin.nsequence = 2 ** 32 - 3
        txin.script_type = 'p2sh'
        redeem_script = bfh(construct_script([
            locktime, opcodes.OP_CHECKLOCKTIMEVERIFY, opcodes.OP_DROP, pubkey, opcodes.OP_CHECKSIG,
        ]))
        txin.redeem_script = redeem_script

        # Build the Transaction Output
        txout = PartialTxOutput.from_address_and_value(
            'yUyx5hJsEwAukTdRy7UihU57rC37Y4y2ZX', sats_less_fees)

        # Build and sign the transaction
        tx = PartialTransaction.from_io([txin], [txout], locktime=locktime, version=1)
        sig = tx.sign_txin(0, privkey)
        txin.script_sig = bfh(construct_script([sig, redeem_script]))

        # note: in testnet3 chain, signature differs (no low-R grinding),
        # so txid there is: a8110bbdd40d65351f615897d98c33cbe33e4ebedb4ba2fc9e8c644423dadc93
        self.assertEqual('5df1c6f7711f2a98d50fd141833f83379d26be06bfea96c1175e36d4330fabe5',
                         tx.txid())
