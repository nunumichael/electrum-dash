# -*- coding: utf-8 -*-

from pprint import pformat

from PyQt5.QtGui import QColor, QPixmap
from PyQt5.QtCore import (Qt, QSortFilterProxyModel, QAbstractTableModel,
                          QModelIndex, pyqtSlot, QVariant, QSize, pyqtSignal,
                          QItemSelectionModel)
from PyQt5.QtWidgets import (QTabBar, QTabWidget, QWidget, QLabel, QPushButton,
                             QTableView, QHeaderView, QAbstractItemView,
                             QHBoxLayout, QVBoxLayout, QDialog, QGridLayout,
                             QTextEdit, QMenu, QComboBox)

from electrum_dash import util
from electrum_dash.dash_tx import (SPEC_PRO_REG_TX, SPEC_PRO_UP_REV_TX,
                                   RevokeReasons, revoke_reason_str)
from electrum_dash.protx import (ProRegTxExc, ProTxManagerExc, ProTxMN,
                                 ProTxService)
from electrum_dash.i18n import _

from .dash_qt import VTabBar
from .protx_wizards import Dip3MasternodeWizard, Dip3FileWizard
from .util import icon_path, read_QIcon, Buttons, CancelButton, OkButton


VALID_MASTERNODE_COLOR = '#008000'


mn_info_dialogs = []  # Otherwise python randomly garbage collects the dialogs


def create_dip3_tab(gui, wallet):
    return Dip3TabWidget(gui, wallet)


class Dip3FilterProxyModel(QSortFilterProxyModel):

    def __init__(self):
        super(Dip3FilterProxyModel, self).__init__()
        self.fstr = ''
        self.setFilterCaseSensitivity(False)

    def filterAcceptsRow(self, row_num, parent):
        if not self.fstr:
            return True

        model = self.sourceModel()
        fstr = self.fstr

        tests = []
        for col in model.filterColumns:
            idx = model.index(row_num, col, parent)
            data = model.data(idx).value().lower()
            tests.append(fstr in data)
        return True in tests

    def filter(self, x):
        self.fstr = x.lower()
        self.invalidateFilter()

    def reload_data(self):
        self.sourceModel().reload_data()

    def reload_alias(self, alias):
        self.sourceModel().reload_alias(alias)


class RegisteredMNsModel(QAbstractTableModel):
    '''Model for DIP3 registered masternodes.'''
    PROTX_HASH = 0
    SERVICE = 1
    VALID = 2

    TOTAL_FIELDS = 3
    filterColumns = [PROTX_HASH, SERVICE, VALID]

    def __init__(self, mn_list):
        super(RegisteredMNsModel, self).__init__()
        self.mn_list = mn_list

        headers = [
            {Qt.DisplayRole: _('ProRegTx hash')},
            {Qt.DisplayRole: _('Service')},
            {Qt.DisplayRole: _('Subset')},
        ]

        for d in headers:
            d[Qt.EditRole] = d[Qt.DisplayRole]
        self.headers = headers
        self.mns = []
        self.row_count = 0

    def reload_data(self):
        self.beginResetModel()
        if self.mn_list:
            mns = [mn.as_dict() for mn in self.mn_list.protx_mns.values()]
            self.mns = sorted(mns, key=lambda x: x['proRegTxHash'])
        else:
            self.mns = []
        self.row_count = len(self.mns)
        self.endResetModel()

    def columnCount(self, parent=QModelIndex()):
        return self.TOTAL_FIELDS

    def rowCount(self, parent=QModelIndex()):
        return self.row_count

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role not in [Qt.DisplayRole, Qt.EditRole]:
            return None
        if orientation != Qt.Horizontal:
            return None

        data = None
        try:
            data = self.headers[section][role]
        except (IndexError, KeyError):
            pass

        return QVariant(data)

    def data(self, index, role=Qt.DisplayRole):
        data = None
        if not index.isValid():
            return QVariant(data)

        mn = self.mns[index.row()]
        i = index.column()

        if i == self.PROTX_HASH and role == Qt.DisplayRole:
            data = mn['proRegTxHash']
        elif i == self.SERVICE:
            if role == Qt.DisplayRole:
                data = mn['service']
            elif role == Qt.TextColorRole:
                if mn['isValid']:
                    data = QColor(VALID_MASTERNODE_COLOR)
        elif i == self.VALID and role == Qt.DisplayRole:
            data = _('Valid') if mn['isValid'] else _('Registered')

        return QVariant(data)


class WalletMNsModel(QAbstractTableModel):
    '''Model for wallet DIP3 masternodes.'''
    ALIAS = 0
    STATE = 1
    KEYS = 2
    SERVICE = 3
    PROTX_HASH = 4

    TOTAL_FIELDS = 5
    filterColumns = [ALIAS, SERVICE, PROTX_HASH]

    STATE_LOADING = 'Loading'
    STATE_UNREGISTERED = 'Unregistered'
    STATE_REGISTERED = 'Registered'  # ProTxHash known but validity unknown
    STATE_VALID = 'Valid'
    STATE_BANNED = 'PoSe Banned'
    STATE_REMOVED = 'Removed'

    STATES_TXT = {
        STATE_LOADING: _('Loading'),
        STATE_UNREGISTERED: _('Unregistered'),
        STATE_REGISTERED: _('Registered'),
        STATE_VALID: _('Valid'),
        STATE_BANNED: _('PoSe Banned'),
        STATE_REMOVED: _('Removed'),
    }

    def __init__(self, manager, mn_list, gui, row_h):
        super(WalletMNsModel, self).__init__()
        self.gui = gui
        self.manager = manager
        self.mn_list = mn_list

        sz = row_h - 10
        mode = Qt.SmoothTransformation
        imgfile = icon_path('dip3_unregistered.png')
        self.icon_unregistered = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_valid.png')
        self.icon_valid = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_banned.png')
        self.icon_banned = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_removed.png')
        self.icon_removed = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_own_op.png')
        self.icon_own_op = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_own_nokey_op.png')
        self.icon_own_nokey_op= QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_own.png')
        self.icon_own = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_own_nokey.png')
        self.icon_own_nokey = QPixmap(imgfile).scaledToWidth(sz, mode=mode)
        imgfile = icon_path('dip3_op.png')
        self.icon_op = QPixmap(imgfile).scaledToWidth(sz, mode=mode)

        headers = [
            {Qt.DisplayRole: _('Alias')},
            {Qt.DisplayRole: _('State')},
            {Qt.DisplayRole: _('Keys')},
            {Qt.DisplayRole: _('Service')},
            {Qt.DisplayRole: _('ProRegTx hash')},
        ]

        for d in headers:
            d[Qt.EditRole] = d[Qt.DisplayRole]
        self.headers = headers
        self.mns = []
        self.mns_states = {}
        self.row_count = 0

    def reload_data(self):
        self.beginResetModel()
        self.mns = sorted(self.manager.mns.values(), key=lambda x: x.alias)
        if self.mn_list:
            protx_mns = {h: mn.as_dict()
                         for h, mn in self.mn_list.protx_mns.items()}
        else:
            protx_mns = {}
        for mn in self.mns:
            h = mn.protx_hash

            if not h:
                self.mns_states[mn.alias] = self.STATE_UNREGISTERED
                continue

            if not self.mn_list:
                self.mns_states[mn.alias] = self.STATE_REGISTERED
                continue

            if self.mn_list.protx_loading:
                self.mns_states[mn.alias] = self.STATE_LOADING
                continue

            protx_mn = protx_mns.get(h)
            if protx_mn:
                if protx_mn['isValid']:
                    self.mns_states[mn.alias] = self.STATE_VALID
                else:
                    self.mns_states[mn.alias] = self.STATE_BANNED
            else:
                self.mns_states[mn.alias] = self.STATE_REMOVED

        self.row_count = len(self.mns)
        self.endResetModel()

    def columnCount(self, parent=QModelIndex()):
        return self.TOTAL_FIELDS

    def rowCount(self, parent=QModelIndex()):
        return self.row_count

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role not in [Qt.DisplayRole]:
            return None
        if orientation != Qt.Horizontal:
            return None
        dataItem = self.headers[section]
        data = dataItem.get(role) if dataItem else None
        return QVariant(data)

    def data(self, index, role=Qt.DisplayRole):
        data = None
        if not index.isValid():
            return None

        mn = self.mns[index.row()]
        w = self.manager.wallet
        has_owner_key = w.is_mine(mn.owner_addr) if mn.owner_addr else False
        i = index.column()

        if i == self.ALIAS and role in (Qt.DisplayRole, Qt.EditRole):
            data = mn.alias
        elif i == self.STATE:
            if role == Qt.DecorationRole:
                state = self.mns_states.get(mn.alias)
                if state in [self.STATE_UNREGISTERED, self.STATE_REGISTERED,
                             self.STATE_LOADING]:
                    data = self.icon_unregistered
                elif state == self.STATE_VALID:
                    data = self.icon_valid
                elif state == self.STATE_BANNED:
                    data = self.icon_banned
                elif state == self.STATE_REMOVED:
                    data = self.icon_removed
                else:
                    data = None
            elif role == Qt.ToolTipRole:
                data = self.STATES_TXT.get(self.mns_states.get(mn.alias),
                                           'Unknown')
        elif i == self.KEYS:
            if role == Qt.DecorationRole:
                if mn.is_owned and mn.is_operated:
                    if has_owner_key:
                        data = self.icon_own_op
                    else:
                        data = self.icon_own_nokey_op
                elif mn.is_owned and not mn.is_operated:
                    if has_owner_key:
                        data = self.icon_own
                    else:
                        data = self.icon_own_nokey
                elif not mn.is_owned and mn.is_operated:
                    data = self.icon_op
                else:
                    data = None
            elif role == Qt.ToolTipRole:
                if mn.is_owned and mn.is_operated:
                    if has_owner_key:
                        data = _('Owner and Operator private keys')
                    else:
                        data = _('Owner with no key and Operator private key')
                elif mn.is_owned and not mn.is_operated:
                    if has_owner_key:
                        data = _('Owner key')
                    else:
                        data = _('Owner with no key')
                elif not mn.is_owned and mn.is_operated:
                    data = _('Operator privete key')
                else:
                    data = None
        elif i == self.SERVICE and role == Qt.DisplayRole:
            data = str(mn.service)
        elif i == self.PROTX_HASH and role == Qt.DisplayRole:
            data = mn.protx_hash

        return QVariant(data)

    def reload_alias(self, alias):
        idx = self.match(self.index(0, 0), Qt.DisplayRole, alias,
                         1, Qt.MatchExactly)
        if not idx:
            return
        idx = idx[0]
        last_col_idx = idx.sibling(idx.row(), self.TOTAL_FIELDS-1)
        self.mns = sorted(self.manager.mns.values(), key=lambda x: x.alias)
        mn = self.manager.mns[alias]
        if mn and not mn.protx_hash:
            self.mns_states[alias] = self.STATE_UNREGISTERED
        self.dataChanged.emit(idx, last_col_idx)

    def setData(self, idx, value, role):
        if role != Qt.EditRole:
            return False

        new_alias = value.strip()
        alias = self.data(idx, Qt.DisplayRole).value()
        if new_alias == alias:
            return False

        try:
            self.manager.rename_mn(alias, new_alias)
            self.mns_states[new_alias] = self.mns_states[alias]
            del self.mns_states[alias]
            self.layoutAboutToBeChanged.emit()
            self.mns = sorted(self.manager.mns.values(), key=lambda x: x.alias)
            new_row = [e[0] for e in enumerate(self.mns)
                       if e[1].alias == new_alias][0]
            new_idx = idx.sibling(new_row, 0)
            self.layoutChanged.emit()
            self.dataChanged.emit(new_idx, new_idx)
        except ProTxManagerExc as e:
            self.gui.show_error(str(e))
            return False
        return True

    def flags(self, idx):
        col = idx.column()
        if col != WalletMNsModel.ALIAS:
            return super(WalletMNsModel, self).flags(idx)
        else:
            return super(WalletMNsModel, self).flags(idx) | Qt.ItemIsEditable


class Dip3TabBar(VTabBar):

    def __init__(self, tab_w):
        super(Dip3TabBar, self).__init__(tab_w)
        self.tab_w = tab_w

        self.data_w = QWidget()
        gl = QGridLayout()
        gl.setColumnStretch(1, 1)
        self.data_w.setLayout(gl)

        heights_l = QLabel('Actual heights:')
        loc_h_l = QLabel('Local:')
        self.local_h = QLabel('0')
        mns_h_l = QLabel('ProTx:')
        self.mns_h = QLabel('0')
        llmq_h_l = QLabel('LLMQ:')
        self.llmq_h = QLabel('0')

        gl.addWidget(heights_l, 0, 0, 1, -1)
        gl.addWidget(loc_h_l, 1, 0)
        gl.addWidget(self.local_h, 1, 2)
        gl.addWidget(mns_h_l, 2, 0)
        gl.addWidget(self.mns_h, 2, 2)
        gl.addWidget(llmq_h_l, 3, 0)
        gl.addWidget(self.llmq_h, 3, 2)

        readiness_l = QLabel('Readiness:')
        protx_ready_l = QLabel('ProTx:')
        self.protx_ready = QLabel('No')
        protx_info_completeness_l = QLabel('ProTx Info:')
        self.protx_info_completeness = QLabel('0%')
        llmq_ready_l = QLabel('LLMQ:')
        self.llmq_ready = QLabel('No')

        gl.addWidget(readiness_l, 4, 0, 1, -1)
        gl.addWidget(protx_ready_l, 5, 0)
        gl.addWidget(self.protx_ready, 5, 2)
        gl.addWidget(protx_info_completeness_l, 6, 0)
        gl.addWidget(self.protx_info_completeness, 6, 2)
        gl.addWidget(llmq_ready_l, 7, 0)
        gl.addWidget(self.llmq_ready, 7, 2)

        self.protx_llmq_reset_btn = QPushButton(_('ProTx/LLMQ Reset'))
        self.protx_llmq_reset_btn.clicked.connect(self.on_protx_llmq_reset)
        gl.addWidget(self.protx_llmq_reset_btn, 8, 0, 1, -1)

        gl2 = QGridLayout()
        gl2.setColumnStretch(0, 1)
        gl2.setRowStretch(0, 1)
        gl2.addWidget(self.data_w, 1, 1)
        gl2.setContentsMargins(0, 0, 0, 0)
        self.tab_w.setLayout(gl2)

    def tabSizeHint(self, index):
        s = QTabBar.tabSizeHint(self, index)
        s.transpose()
        return QSize(max(s.width(), self.data_w.sizeHint().width()),
                     s.height())

    def resizeEvent(self, *args):
        super(Dip3TabBar, self).resizeEvent(*args)
        self.data_w.setMinimumWidth(self.width())

    def update_stats(self, stats):
        (local_h, mns_h, llmq_h,
         protx_ready, llmq_ready, protx_info_completeness) = stats
        self.local_h.setText(str(local_h))
        self.mns_h.setText(str(mns_h))
        self.llmq_h.setText(str(llmq_h))
        self.protx_ready.setText(protx_ready)
        self.llmq_ready.setText(llmq_ready)
        self.protx_info_completeness.setText(protx_info_completeness)

    @pyqtSlot()
    def on_protx_llmq_reset(self):
        mn_list = self.tab_w.mn_list
        if self.tab_w.gui.question(mn_list.RESET_WARN_MSG):
            mn_list.reset()


class Dip3TabWidget(QTabWidget):
    # Signals need to notify from not Qt thread
    alias_updated = pyqtSignal(str)
    diff_updated = pyqtSignal(dict)
    info_updated = pyqtSignal(str)
    network_updated = pyqtSignal()

    def __init__(self, gui, wallet, *args, **kwargs):
        QTabWidget.__init__(self, *args, **kwargs)
        self.tab_bar = Dip3TabBar(self)
        self.setTabBar(self.tab_bar)
        self.setTabPosition(QTabWidget.East)
        self.gui = gui
        self.wallet = wallet
        self.manager = wallet.protx_manager
        self.mn_list = gui.network.mn_list if gui.network else None
        self.reg_cur_protx = ''
        self.reg_cur_idx = None
        self.w_cur_alias = ''
        self.w_cur_state = ''
        self.w_cur_idx = None

        self.wallet_mn_tab = self.create_wallet_mn_tab()
        if self.mn_list:
            self.registerd_mn_tab = self.create_registered_mn_tab()
        self.searchable_list = self.w_model
        self.currentChanged.connect(self.on_tabs_current_changed)

        if self.mn_list:
            self.tab_bar.update_stats(self.get_stats())
            util.register_callback(self.on_mn_list_diff_updated,
                                   ['mn-list-diff-updated'])
            util.register_callback(self.on_mn_list_info_updated,
                                   ['mn-list-info-updated'])
        if self.gui.network:
            util.register_callback(self.on_cb_network_updated,
                                   ['network_updated'])
        util.register_callback(self.on_manager_alias_updated,
                               ['manager-alias-updated'])
        self.alias_updated.connect(self.on_alias_updated)
        self.diff_updated.connect(self.on_diff_updated)
        self.info_updated.connect(self.on_info_updated)
        self.network_updated.connect(self.on_network_updated)

    def unregister_callbacks(self):
        if self.mn_list:
            util.unregister_callback(self.on_mn_list_diff_updated)
            util.unregister_callback(self.on_mn_list_info_updated)
        if self.gui.network:
            util.unregister_callback(self.on_cb_network_updated)
        util.unregister_callback(self.on_manager_alias_updated)

    def get_stats(self):
        mn_list = self.mn_list
        local_height = self.gui.network.get_local_height()
        protx_height = mn_list.protx_height
        llmq_height = mn_list.llmq_human_height
        protx_ready = 'Yes' if mn_list.protx_ready else 'No'
        llmq_ready = 'Yes' if mn_list.llmq_ready else 'No'
        completeness = mn_list.protx_info_completeness
        protx_info_completeness = '%s%%' % round(completeness*100)
        return (local_height, protx_height, llmq_height,
                protx_ready, llmq_ready, protx_info_completeness)

    @pyqtSlot()
    def on_tabs_current_changed(self):
        cur_widget = self.currentWidget()
        if cur_widget == self.wallet_mn_tab:
            self.searchable_list = self.w_model
        else:
            self.searchable_list = self.reg_model

    def on_mn_list_diff_updated(self, key, value):
        self.diff_updated.emit(value)

    def on_mn_list_info_updated(self, key, value):
        self.info_updated.emit(value)

    def on_manager_alias_updated(self, key, value):
        self.alias_updated.emit(value)

    def on_cb_network_updated(self, key):
        self.network_updated.emit()

    @pyqtSlot(str)
    def on_alias_updated(self, alias):
        self.w_model.reload_data()
        self.restore_w_selection()

    @pyqtSlot()
    def on_network_updated(self):
        self.tab_bar.update_stats(self.get_stats())

    @pyqtSlot(dict)
    def on_diff_updated(self, value):
        state = value.get('state', self.mn_list.DIP3_DISABLED)
        if self.mn_list.load_mns and not self.mn_list.protx_loading:
            self.reg_model.reload_data()
            self.restore_reg_selection()
        self.w_model.reload_data()
        self.restore_w_selection()

        if state == self.mn_list.DIP3_ENABLED:
            self.reg_search_btn.setEnabled(True)
        else:
            self.reg_search_btn.setEnabled(False)

        self.tab_bar.update_stats(self.get_stats())
        self.update_registered_label()
        self.update_wallet_label()

    @pyqtSlot(str)
    def on_info_updated(self, value):
        self.tab_bar.update_stats(self.get_stats())

    def registered_label(self):
        if not self.mn_list:
            return _('Offline')

        state = self.mn_list.protx_state
        if state == self.mn_list.DIP3_DISABLED:
            return _('DIP3 Masternodes is currently disabled.')

        count = len(self.mn_list.protx_mns)
        connected = self.gui.network.is_connected()
        loading = connected and self.mn_list.protx_loading
        ready = _('Loading') if loading else _('Found')
        return (_('%s %s registered DIP3 Masternodes.') % (ready, count))

    def update_registered_label(self):
        self.reg_label.setText(self.registered_label())

    def wallet_label(self):
        mns = self.manager.mns
        count = len(mns)
        mn_str = _('Masternode') if count == 1 else _('Masternodes')
        def_label_str = _('Wallet contains %s DIP3 %s.') % (count, mn_str)

        if not self.mn_list:
            return def_label_str

        state = self.mn_list.protx_state
        if state == self.mn_list.DIP3_DISABLED:
            return (_('DIP3 Masternodes is currently disabled.'))

        connected = self.gui.network.is_connected()
        loading = connected and self.mn_list.protx_loading
        if loading:
            height = self.mn_list.protx_height
            return (_('Loading DIP3 data at Height: %s.') % height)

        return def_label_str

    def update_wallet_label(self):
        self.w_label.setText(self.wallet_label())

    def create_registered_mn_tab(self):
        w = QWidget()
        hw = QWidget()

        self.reg_label = QLabel(self.registered_label())
        self.reg_search_btn = QPushButton(_('Search'))
        self.reg_search_btn.clicked.connect(self.on_reg_search)

        src_model = RegisteredMNsModel(self.mn_list)
        self.reg_model = Dip3FilterProxyModel()
        self.reg_model.setSourceModel(src_model)

        self.reg_view = QTableView()
        self.reg_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.reg_view.customContextMenuRequested.connect(self.create_reg_menu)
        self.reg_hheader = QHeaderView(Qt.Horizontal, self.reg_view)
        self.reg_hheader.setSectionResizeMode(QHeaderView.ResizeToContents)
        self.reg_hheader.setStretchLastSection(True)

        self.reg_view.setHorizontalHeader(self.reg_hheader)
        self.reg_view.verticalHeader().hide()
        self.reg_view.setModel(self.reg_model)
        self.reg_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.reg_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.reg_view.doubleClicked.connect(self.reg_mn_dbl_clicked)

        sel_model = self.reg_view.selectionModel()
        sel_model.selectionChanged.connect(self.on_reg_selection_changed)

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(self.reg_label)
        hbox.addStretch(1)
        hbox.addWidget(self.reg_search_btn)
        hw.setLayout(hbox)
        vbox.addWidget(hw)
        vbox.addWidget(self.reg_view)
        w.setLayout(vbox)
        self.addTab(w, read_QIcon('tab_search.png'), _('Registered MNs'))
        if not self.mn_list.protx_loading:
            self.reg_model.reload_data()
            self.restore_reg_selection()
        return w

    def create_reg_menu(self, position):
        menu = QMenu()
        h = self.reg_cur_protx
        menu.addAction(_('Details'), lambda: self.show_protx_hash_info(h))
        menu.exec_(self.reg_view.viewport().mapToGlobal(position))

    def create_wallet_mn_tab(self):
        w = QWidget()
        hw = QWidget()

        self.w_label = QLabel(self.wallet_label())
        self.w_add_btn = QPushButton(_('Add / Import'))
        self.w_file_btn = QPushButton(_('File'))
        self.w_del_btn = QPushButton(_('Remove'))
        self.w_clear_protx_btn = QPushButton(_('Clear ProTxHash'))
        self.w_up_params_btn = QPushButton(_('Update Params'))
        self.w_protx_btn = QPushButton(_('Register'))
        self.w_up_reg_btn = QPushButton(_('Update Registrar'))
        self.w_up_rev_btn = QPushButton(_('Revoke'))
        self.w_new_bls_bnt = QPushButton(_('New BLS Keys'))
        self.w_up_srv_btn = QPushButton(_('Update Service'))
        self.w_add_btn.clicked.connect(self.on_add_masternode)
        self.w_file_btn.clicked.connect(self.on_file)
        self.w_del_btn.clicked.connect(self.on_del_masternode)
        self.w_clear_protx_btn.clicked.connect(self.on_clear_protx)
        self.w_up_params_btn.clicked.connect(self.on_update_params)
        self.w_protx_btn.clicked.connect(self.on_make_pro_reg_tx)
        self.w_up_reg_btn.clicked.connect(self.on_make_pro_up_reg_tx)
        self.w_up_rev_btn.clicked.connect(self.on_make_pro_up_rev_tx)
        self.w_new_bls_bnt.clicked.connect(self.on_new_bls)
        self.w_up_srv_btn.clicked.connect(self.on_make_pro_up_srv_tx)
        self.hide_mn_buttons()

        self.w_view = QTableView()
        self.w_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.w_view.customContextMenuRequested.connect(self.create_wallet_menu)
        self.w_hheader = QHeaderView(Qt.Horizontal, self.w_view)
        self.w_hheader.setSectionResizeMode(QHeaderView.ResizeToContents)
        self.w_hheader.setStretchLastSection(True)

        self.w_view.setHorizontalHeader(self.w_hheader)
        self.w_view.verticalHeader().hide()
        self.w_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.w_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.w_view.doubleClicked.connect(self.w_mn_dbl_clicked)

        row_h = self.w_view.verticalHeader().defaultSectionSize()
        self.w_hheader.setMinimumSectionSize(row_h)
        src_model = WalletMNsModel(self.manager, self.mn_list, self.gui, row_h)
        src_model.dataChanged.connect(self.w_data_changed)
        self.w_model = Dip3FilterProxyModel()
        self.w_model.setSourceModel(src_model)
        self.w_view.setModel(self.w_model)

        sel_model = self.w_view.selectionModel()
        sel_model.selectionChanged.connect(self.on_wallet_selection_changed)
        self.w_model.modelReset.connect(self.on_wallet_model_reset)

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(self.w_label)
        hbox.addStretch(1)
        hbox.addWidget(self.w_add_btn)
        hw.setLayout(hbox)
        vbox.addWidget(hw)
        vbox.addWidget(self.w_view)
        self.addTab(w, read_QIcon('tab_dip3.png'), _('Wallet MNs'))
        if self.mn_list and not self.mn_list.protx_loading:
            self.w_model.reload_data()
            self.restore_w_selection()

        hw = QWidget()
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self.w_file_btn)
        hbox.addWidget(self.w_del_btn)
        hbox.addWidget(self.w_clear_protx_btn)
        hbox.addWidget(self.w_up_params_btn)
        hbox.addWidget(self.w_protx_btn)
        hbox.addWidget(self.w_up_reg_btn)
        hbox.addWidget(self.w_up_rev_btn)
        hbox.addWidget(self.w_new_bls_bnt)
        hbox.addWidget(self.w_up_srv_btn)
        hw.setLayout(hbox)
        vbox.addWidget(hw)
        w.setLayout(vbox)
        return w

    @pyqtSlot()
    def on_reg_search(self):
        self.gui.toggle_search()

    def create_wallet_menu(self, position):
        a = self.w_cur_alias
        s = self.w_cur_state
        i = self.w_cur_idx

        menu = QMenu()
        if not i or s == WalletMNsModel.STATE_LOADING:
            menu.addAction(_('Add / Import'), self.on_add_masternode)
            menu.addAction(_('File'), self.on_file)
            menu.exec_(self.w_view.viewport().mapToGlobal(position))
            return

        mn = self.manager.mns.get(a)
        owned = mn.is_owned
        operated = mn.is_operated
        protx_hash = mn.protx_hash
        removed = (s == WalletMNsModel.STATE_REMOVED)

        menu.addAction(_('Remove'), self.on_del_masternode)

        if removed:
            menu.addAction(_('Clear ProTxHash'), self.on_clear_protx)

        if not protx_hash:
            menu.addAction(_('Update Params'), self.on_update_params)

        if owned and not protx_hash:
            menu.addAction(_('Register'), self.on_make_pro_reg_tx)

        if (owned and protx_hash and not removed
                and self.wallet.is_mine(mn.owner_addr)):
            menu.addAction(_('Update Registrar'), self.on_make_pro_up_reg_tx)

        if operated and not owned and protx_hash and not removed:
            menu.addAction(_('Revoke'), self.on_make_pro_up_rev_tx)

        if operated and not owned and protx_hash:
            menu.addAction(_('New BLS Keys'), self.on_new_bls)

        if operated and protx_hash and not removed:
            menu.addAction(_('Update Service'), self.on_make_pro_up_srv_tx)

        menu.addSeparator()
        menu.addAction(_('Rename Alias'),
                       lambda: self.w_view.edit(i))
        menu.addSeparator()
        menu.addAction(_('Details'), lambda: self.show_alias_info(a))

        menu.addSeparator()
        menu.addAction(_('Add / Import'), self.on_add_masternode)
        menu.addAction(_('File'), self.on_file)

        menu.exec_(self.w_view.viewport().mapToGlobal(position))

    @pyqtSlot()
    def on_new_bls(self):
        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or not mn.is_operated:
            return
        start_id = Dip3MasternodeWizard.BLS_KEYS_PAGE
        wiz = Dip3MasternodeWizard(self, mn=mn, start_id=start_id)
        wiz.open()

    @pyqtSlot()
    def on_update_params(self):
        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or mn.protx_hash:
            return
        if mn.is_owned:
            start_id = Dip3MasternodeWizard.COLLATERAL_PAGE
        else:
            start_id = Dip3MasternodeWizard.SERVICE_PAGE
        wiz = Dip3MasternodeWizard(self, mn=mn, start_id=start_id)
        wiz.open()

    @pyqtSlot()
    def on_make_pro_reg_tx(self):
        alias = self.w_cur_alias
        try:
            pro_reg_tx = self.manager.prepare_pro_reg_tx(alias)
        except ProRegTxExc as e:
            self.gui.show_error(e)
            return
        mn = self.manager.mns.get(alias)
        gui = self.gui
        gui.do_clear()
        if mn.collateral.is_null:
            gui.amount_e.setText('1000')
        mn_addrs = [mn.owner_addr, mn.voting_addr, mn.payout_address]
        for addr in self.wallet.get_unused_addresses():
            if addr not in mn_addrs:
                gui.payto_e.setText(addr)
                break
        gui.extra_payload.set_extra_data(SPEC_PRO_REG_TX, pro_reg_tx, alias)
        gui.show_extra_payload()
        gui.tabs.setCurrentIndex(self.gui.tabs.indexOf(self.gui.send_tab))

    @pyqtSlot()
    def on_file(self):
        wiz = Dip3FileWizard(self)
        wiz.open()

    @pyqtSlot()
    def on_add_masternode(self):
        wiz = Dip3MasternodeWizard(self)
        wiz.open()

    @pyqtSlot()
    def on_make_pro_up_srv_tx(self):
        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or not mn.protx_hash:
            return
        wiz = Dip3MasternodeWizard(self, mn=mn,
                                   start_id=Dip3MasternodeWizard.UPD_SRV_PAGE)
        wiz.open()

    @pyqtSlot()
    def on_make_pro_up_rev_tx(self):
        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or not mn.protx_hash:
            return
        d = RevokeOperatiorDialog(self, mn)
        if d.exec_() and d.reason is not None:
            try:
                rev_tx = self.manager.prepare_pro_up_rev_tx(mn.alias, d.reason)
            except ProRegTxExc as e:
                self.gui.show_error(e)
                return
            gui = self.gui
            gui.do_clear()
            mn_addrs = [mn.owner_addr, mn.voting_addr, mn.payout_address]
            for addr in self.manager.wallet.get_unused_addresses():
                if addr not in mn_addrs:
                    gui.payto_e.setText(addr)
                    break
            tx_type = SPEC_PRO_UP_REV_TX
            gui.extra_payload.set_extra_data(tx_type, rev_tx, mn.alias)
            gui.show_extra_payload()
            gui.tabs.setCurrentIndex(gui.tabs.indexOf(gui.send_tab))

    @pyqtSlot()
    def on_make_pro_up_reg_tx(self):
        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or not mn.protx_hash:
            return
        wiz = Dip3MasternodeWizard(self, mn=mn,
                                   start_id=Dip3MasternodeWizard.UPD_REG_PAGE)
        wiz.open()

    @pyqtSlot()
    def on_del_masternode(self):
        alias = self.w_cur_alias
        mn = self.manager.mns.get(alias)
        if not mn:
            return
        if not self.gui.question(_('Do you want to remove the masternode '
                                   'configuration for %s?') % alias):
            return
        if mn.protx_hash:
            if not self.gui.question(_('Masternode %s has ProRegTxHash '
                                       'already set. Are you sure?') % alias):
                return
        self.manager.remove_mn(self.w_cur_alias)
        self.w_model.reload_data()

    @pyqtSlot()
    def on_clear_protx(self):
        alias = self.w_cur_alias
        mn = self.manager.mns.get(alias)
        if not mn:
            return
        q = '\n'.join([_('Clearing of ProTxHash allow reuse of masternode.'),
                       _('Do you want to clear ProTxHash for %s?') % alias])
        if not self.gui.question(q):
            return
        if not mn.service.port:  # service cleared on Revoke operator
            mn.service = ProTxService('', ProTxMN.default_port())
        mn.protx_hash = ''
        self.manager.update_mn(alias, mn)
        self.w_model.reload_alias(alias)

    @pyqtSlot()
    def on_reg_selection_changed(self):
        sel = self.reg_view.selectionModel()
        if sel.hasSelection():
            idx = sel.selectedRows()[0]
            self.reg_cur_idx = idx
            self.reg_cur_protx = idx.data()
        else:
            self.reg_cur_idx = None
            self.reg_cur_protx = ''

    def restore_reg_selection(self):
        cur_idx = self.reg_cur_idx
        if not cur_idx:
            return
        row_count = self.reg_model.sourceModel().row_count
        if row_count == 0 or row_count <= cur_idx.row():
            self.reg_cur_idx = None
            self.reg_cur_protx = ''
        else:
            self.reg_view.selectRow(cur_idx.row())

    def hide_mn_buttons(self):
        self.w_del_btn.hide()
        self.w_clear_protx_btn.hide()
        self.w_up_params_btn.hide()
        self.w_protx_btn.hide()
        self.w_up_reg_btn.hide()
        self.w_up_rev_btn.hide()
        self.w_new_bls_bnt.hide()
        self.w_up_srv_btn.hide()

    @pyqtSlot()
    def on_wallet_model_reset(self):
        self.update_wallet_label()
        self.hide_mn_buttons()

    @pyqtSlot()
    def on_wallet_selection_changed(self):
        sel = self.w_view.selectionModel()
        if not sel.hasSelection():
            self.w_cur_alias = ''
            self.w_cur_state = ''
            self.w_cur_idx = None
            self.hide_mn_buttons()
            return

        idx = sel.selectedRows()[0]
        self.w_cur_alias = idx.data()
        self.w_cur_state = idx.sibling(idx.row(), 1).data(Qt.ToolTipRole)
        self.w_cur_idx = idx

        mn = self.manager.mns.get(self.w_cur_alias)
        if not mn or self.w_cur_state == WalletMNsModel.STATE_LOADING:
            return

        owned = mn.is_owned
        operated = mn.is_operated
        protx_hash = mn.protx_hash
        removed = (self.w_cur_state == WalletMNsModel.STATE_REMOVED)

        self.w_del_btn.show()

        if removed:
            self.w_clear_protx_btn.show()

        if not protx_hash:
            self.w_up_params_btn.show()
        else:
            self.w_up_params_btn.hide()

        if operated and not owned and protx_hash:
            self.w_new_bls_bnt.show()
        else:
            self.w_new_bls_bnt.hide()

        if owned and not protx_hash:
            self.w_protx_btn.show()
        else:
            self.w_protx_btn.hide()

        if operated and not owned and protx_hash and not removed:
            self.w_up_rev_btn.show()
        else:
            self.w_up_rev_btn.hide()

        if operated and protx_hash and not removed:
            self.w_up_srv_btn.show()
        else:
            self.w_up_srv_btn.hide()

        if (owned and protx_hash and not removed
                and self.wallet.is_mine(mn.owner_addr)):
            self.w_up_reg_btn.show()
        else:
            self.w_up_reg_btn.hide()

    def restore_w_selection(self):
        cur_idx = self.w_cur_idx
        if not cur_idx:
            return
        row_count = self.w_model.sourceModel().row_count
        if row_count == 0 or row_count <= cur_idx.row():
            self.w_cur_alias = ''
            self.w_cur_state = ''
            self.w_cur_idx = None
        else:
            self.w_view.selectRow(cur_idx.row())

    @pyqtSlot(QModelIndex)
    def reg_mn_dbl_clicked(self, idx):
        row_idx = idx.sibling(idx.row(), 0)
        self.show_protx_hash_info(row_idx.data())

    def show_protx_hash_info(self, protx_hash):
        d = Dip3MNInfoDialog(self, protx_hash=protx_hash)
        mn_info_dialogs.append(d)
        d.show()

    @pyqtSlot(QModelIndex)
    def w_mn_dbl_clicked(self, idx):
        col = idx.column()
        if col == WalletMNsModel.ALIAS:
            return
        row_idx = idx.sibling(idx.row(), 0)
        self.show_alias_info(row_idx.data())

    def show_alias_info(self, alias):
        d = Dip3MNInfoDialog(self, alias=alias)
        mn_info_dialogs.append(d)
        d.show()

    @pyqtSlot(QModelIndex)
    def w_data_changed(self, idx):
        sel_model = self.w_view.selectionModel()
        sel_model.clear()
        sel_model.setCurrentIndex(idx,
                                  QItemSelectionModel.ClearAndSelect |
                                  QItemSelectionModel.Rows)
        sel_model.select(idx,
                         QItemSelectionModel.ClearAndSelect |
                         QItemSelectionModel.Rows)


class Dip3MNInfoDialog(QDialog):
    # Signals need to notify from not Qt thread
    diff_updated = pyqtSignal(dict)
    info_updated = pyqtSignal()

    def __init__(self, parent, protx_hash=None, alias=None):
        '''
        Show information about registred Masternodes with given prot_hash,
        or Masternodes in manager with given alias.
        '''
        super(Dip3MNInfoDialog, self).__init__(parent)
        self.setMinimumSize(950, 450)
        self.setWindowIcon(read_QIcon('electrum-dash.png'))

        self.parent = parent
        self.gui = parent.gui
        self.manager = parent.manager
        self.mn_list = parent.mn_list
        self.diff_updated.connect(self.on_diff_updated)
        self.info_updated.connect(self.on_info_updated)

        if alias:
            self.mn = self.manager.mns.get(alias)
        else:
            self.mn = None

        if self.mn:
            self.protx_hash = self.mn.protx_hash
            self.setWindowTitle(_('%s Dip3 Masternode Info') % alias)
        elif protx_hash:
            self.protx_hash = protx_hash
            self.setWindowTitle(_('%s... Dip3 Masternode Info')
                                % protx_hash[:32])

        if self.mn_list and self.protx_hash:
            mn_list = self.mn_list
            sml_entry = mn_list.protx_mns.get(self.protx_hash, {})
            self.diff_info = sml_entry.as_dict() if sml_entry else {}
            util.register_callback(self.on_mn_list_diff_updated,
                                   ['mn-list-diff-updated'])
            util.register_callback(self.on_mn_list_info_updated,
                                   ['mn-list-info-updated'])
            self.info = mn_list.protx_info.get(self.protx_hash, {})
            if not self.info and self.gui.network.is_connected():
                self.gui.network.run_from_another_thread(
                    self.gui.network.request_protx_info(self.protx_hash)
                )
        else:
            self.diff_info = {}
            self.info = {}

        layout = QGridLayout()
        self.setLayout(layout)
        self.tabs = QTabWidget(self)
        self.close_btn = b = QPushButton(_('Close'))
        b.setDefault(True)
        b.clicked.connect(self.close)
        layout.addWidget(self.tabs, 0, 0, 1, -1)
        layout.setColumnStretch(0, 1)
        layout.addWidget(b, 1, 1)

        if self.mn:
            self.mn_tab = QWidget()
            self.mn_label = QLabel(_('Wallet Masternode: %s') % self.mn.alias)
            self.mn_view = QTextEdit()
            self.mn_view.setReadOnly(True)
            self.mn_view.setText(pformat(self.mn.as_dict()))
            mn_vbox = QVBoxLayout()
            mn_vbox.addWidget(self.mn_label)
            mn_vbox.addWidget(self.mn_view)
            self.mn_tab.setLayout(mn_vbox)
            self.tabs.addTab(self.mn_tab, _('Wallet'))
        if self.protx_hash:
            self.diff_info_tab = QWidget()
            self.diff_info_view = QTextEdit()
            self.diff_info_view.setReadOnly(True)
            self.diff_info_view.setText(pformat(self.diff_info))
            diff_info_vbox = QVBoxLayout()
            diff_info_vbox.addWidget(self.diff_info_view)
            self.diff_info_tab.setLayout(diff_info_vbox)
            self.tabs.addTab(self.diff_info_tab, _('protx.diff data (merkle '
                                                   'root verified)'))

            self.info_tab = QWidget()
            self.info_view = QTextEdit()
            self.info_view.setReadOnly(True)
            self.info_view.setText(pformat(self.info))
            info_vbox = QVBoxLayout()
            info_vbox.addWidget(self.info_view)
            self.info_tab.setLayout(info_vbox)
            self.tabs.addTab(self.info_tab, _('protx.info data (unverified)'))

    def on_mn_list_diff_updated(self, key, value):
        self.diff_updated.emit(value)

    def on_mn_list_info_updated(self, key, info_hash):
        if self.protx_hash and self.protx_hash == info_hash:
            mn_list = self.mn_list
            self.info = mn_list.protx_info.get(self.protx_hash, {})
            self.info_updated.emit()

    @pyqtSlot(dict)
    def on_diff_updated(self, value):
        diff_hashes = value.get('diff_hashes', [])
        deleted_mns = value.get('deleted_mns', [])
        if self.protx_hash in diff_hashes:
            mn_list = self.mn_list
            sml_entry = mn_list.protx_mns.get(self.protx_hash, {})
            self.diff_info = sml_entry.as_dict() if sml_entry else {}
            self.diff_info_view.setText(pformat(self.diff_info))
        elif self.protx_hash in deleted_mns:
            self.diff_info = {}
            self.info = self.diff_info
            self.diff_info_view.setText(pformat(self.diff_info))
            self.info_updated.emit()

    @pyqtSlot()
    def on_info_updated(self):
        self.info_view.setText(pformat(self.info))

    def reject(self):
        self.close()

    def closeEvent(self, event):
        event.accept()
        if self.mn_list and self.protx_hash:
            util.unregister_callback(self.on_mn_list_diff_updated)
            util.unregister_callback(self.on_mn_list_info_updated)
        try:
            mn_info_dialogs.remove(self)
        except ValueError:
            pass


class RevokeOperatiorDialog(QDialog):

    def __init__(self, parent, mn):
        super(RevokeOperatiorDialog, self).__init__(parent)
        self.setWindowTitle(_('Revoke operator'))
        self.setWindowIcon(read_QIcon('electrum-dash.png'))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_('Revoke operator for: {}').format(mn.alias)))
        vbox.addStretch(1)
        self.setLayout(vbox)
        vbox.addWidget(QLabel(_('Select revocation reason:')))
        self.reason_cb = QComboBox()
        vbox.addWidget(self.reason_cb)
        self.ok_btn = OkButton(self)
        self.ok_btn.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_btn))
        for reason in RevokeReasons:
            self.reason_cb.addItem(revoke_reason_str(reason), reason)
        self.reason_cb.setCurrentIndex(-1)
        self.reason_cb.currentIndexChanged.connect(self.on_reason_changed)
        self.reason = None

    def on_reason_changed(self, idx):
        self.reason = self.reason_cb.itemData(idx)
        self.ok_btn.setEnabled(True)
