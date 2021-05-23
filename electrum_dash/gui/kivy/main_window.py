import re
import os
import sys
import time
import datetime
import traceback
from decimal import Decimal
import threading
import asyncio
from typing import TYPE_CHECKING, Optional, Union, Callable, Sequence

from electrum_dash.dash_ps_util import (PSPossibleDoubleSpendError,
                                        PSSpendToPSAddressesError)
from electrum_dash.storage import WalletStorage, StorageReadWriteError
from electrum_dash.wallet_db import WalletDB
from electrum_dash.wallet import Wallet, InternalAddressCorruption, Abstract_Wallet
from electrum_dash.wallet import update_password_for_directory

from electrum_dash.plugin import run_hook
from electrum_dash import util
from electrum_dash.util import (profiler, InvalidPassword, send_exception_to_crash_reporter,
                           format_satoshis, format_satoshis_plain, format_fee_satoshis)
from electrum_dash.invoices import PR_PAID, PR_FAILED
from electrum_dash import blockchain
from electrum_dash.network import Network, TxBroadcastError, BestEffortRequestFailed
from electrum_dash.interface import PREFERRED_NETWORK_PROTOCOL, ServerAddr
from electrum_dash.logging import Logger

from electrum_dash.gui import messages
from .i18n import _
from . import KIVY_GUI_PATH

from kivy.app import App
from kivy.core.window import Window
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty, BooleanProperty, NumericProperty)
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.factory import Factory
from kivy.metrics import inch
from kivy.lang import Builder
from .uix.dialogs.password_dialog import OpenWalletDialog, ChangePasswordDialog, PincodeDialog, PasswordDialog
from .uix.dialogs.choice_dialog import ChoiceDialog

## lazy imports for factory so that widgets can be used in kv
#Factory.register('InstallWizard', module='electrum_dash.gui.kivy.uix.dialogs.installwizard')
#Factory.register('InfoBubble', module='electrum_dash.gui.kivy.uix.dialogs')
#Factory.register('OutputList', module='electrum_dash.gui.kivy.uix.dialogs')
#Factory.register('OutputItem', module='electrum_dash.gui.kivy.uix.dialogs')

from .uix.dialogs.installwizard import InstallWizard
from .uix.dialogs import InfoBubble, crash_reporter
from .uix.dialogs import OutputList, OutputItem
from .uix.dialogs import TopLabel, RefLabel
from .uix.dialogs.question import Question
from .uix.dialogs.dash_kivy import TorWarnDialog
from .uix.dialogs.warn_dialog import WarnDialog
from .uix.dialogs.question import Question

#from kivy.core.window import Window
#Window.softinput_mode = 'below_target'

# delayed imports: for startup speed on android
notification = app = ref = None

# register widget cache for keeping memory down timeout to forever to cache
# the data
Cache.register('electrum_dash_widgets', timeout=0)

from kivy.uix.screenmanager import Screen
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.label import Label
from kivy.core.clipboard import Clipboard

Factory.register('TabbedCarousel', module='electrum_dash.gui.kivy.uix.screens')

# Register fonts without this you won't be able to use bold/italic...
# inside markup.
from kivy.core.text import Label
Label.register(
    'Roboto',
    KIVY_GUI_PATH + '/data/fonts/Roboto.ttf',
    KIVY_GUI_PATH + '/data/fonts/Roboto.ttf',
    KIVY_GUI_PATH + '/data/fonts/Roboto-Bold.ttf',
    KIVY_GUI_PATH + '/data/fonts/Roboto-Bold.ttf',
)


from electrum_dash.util import (NoDynamicFeeEstimates, NotEnoughFunds,
                                XAZAB_BIP21_URI_SCHEME, PAY_BIP21_URI_SCHEME,
                                UserFacingException)

if TYPE_CHECKING:
    from . import ElectrumGui
    from electrum_dash.simple_config import SimpleConfig
    from electrum_dash.plugin import Plugins
    from electrum_dash.paymentrequest import PaymentRequest


ATLAS_ICON = f'atlas://{KIVY_GUI_PATH}/theming/light/%s'


class ElectrumWindow(App, Logger):

    electrum_config = ObjectProperty(None)
    language = StringProperty('en')

    # properties might be updated by the network
    num_blocks = NumericProperty(0)
    num_nodes = NumericProperty(0)
    server_host = StringProperty('')
    server_port = StringProperty('')
    num_chains = NumericProperty(0)
    blockchain_name = StringProperty('')
    fee_status = StringProperty('Fee')
    balance = StringProperty('')
    fiat_balance = StringProperty('')
    is_fiat = BooleanProperty(False)
    blockchain_forkpoint = NumericProperty(0)

    auto_connect = BooleanProperty(False)
    def on_auto_connect(self, instance, x):
        net_params = self.network.get_parameters()
        net_params = net_params._replace(auto_connect=self.auto_connect)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))
    def toggle_auto_connect(self, x):
        self.auto_connect = not self.auto_connect

    oneserver = BooleanProperty(False)
    def on_oneserver(self, instance, x):
        net_params = self.network.get_parameters()
        net_params = net_params._replace(oneserver=self.oneserver)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))
    def toggle_oneserver(self, x):
        self.oneserver = not self.oneserver

    tor_auto_on_bp = BooleanProperty()
    def toggle_tor_auto_on(self, x):
        self.tor_auto_on_bp = not self.electrum_config.get('tor_auto_on', True)
        self.electrum_config.set_key('tor_auto_on', self.tor_auto_on_bp, True)

    fiat_bypass_tor_bp = BooleanProperty()
    def toggle_fiat_bypass_tor(self, x):
        self.fiat_bypass_tor_bp = \
            not self.electrum_config.get('fiat_bypass_tor', False)
        self.electrum_config.set_key('fiat_bypass_tor',
                                     self.fiat_bypass_tor_bp, True)
        coro = self.network.restart()
        self.network.run_from_another_thread(coro)

    proxy_str = StringProperty('')
    def update_proxy_str(self, proxy: dict):
        mode = proxy.get('mode')
        host = proxy.get('host')
        port = proxy.get('port')
        self.proxy_str = (host + ':' + port) if mode else _('None')

    def choose_server_dialog(self, popup):
        protocol = PREFERRED_NETWORK_PROTOCOL
        def cb2(server_str):
            popup.ids.server_str.text = server_str
        servers = self.network.get_servers()
        server_choices = {}
        for _host, d in sorted(servers.items()):
            port = d.get(protocol)
            if port:
                server = ServerAddr(_host, port, protocol=protocol)
                server_choices[server.net_addr_str()] = _host
        ChoiceDialog(_('Choose a server'), server_choices, popup.ids.server_str.text, cb2).open()

    def maybe_switch_to_server(self, server_str: str):
        net_params = self.network.get_parameters()
        try:
            server = ServerAddr.from_str_with_inference(server_str)
            if not server: raise Exception("failed to parse")
        except Exception as e:
            self.show_error(_("Invalid server details: {}").format(repr(e)))
            return
        net_params = net_params._replace(server=server)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    def choose_blockchain_dialog(self, dt):
        chains = self.network.get_blockchains()
        def cb(name):
            with blockchain.blockchains_lock: blockchain_items = list(blockchain.blockchains.items())
            for chain_id, b in blockchain_items:
                if name == b.get_name():
                    self.network.run_from_another_thread(self.network.follow_chain_given_id(chain_id))
        chain_objects = [blockchain.blockchains.get(chain_id) for chain_id in chains]
        chain_objects = filter(lambda b: b is not None, chain_objects)
        names = [b.get_name() for b in chain_objects]
        if len(names) > 1:
            cur_chain = self.network.blockchain().get_name()
            ChoiceDialog(_('Choose your chain'), names, cur_chain, cb).open()

    use_change = BooleanProperty(False)
    def on_use_change(self, instance, x):
        if self.wallet:
            self.wallet.use_change = self.use_change
            self.wallet.db.put('use_change', self.use_change)
            self.wallet.save_db()

    use_unconfirmed = BooleanProperty(False)
    def on_use_unconfirmed(self, instance, x):
        self.electrum_config.set_key('confirmed_only', not self.use_unconfirmed, True)

    def switch_to_send_screen(func):
        # try until send_screen is available
        def wrapper(self, *args):
            f = lambda dt: (bool(func(self, *args) and False) if self.send_screen else bool(self.switch_to('send') or True)) if self.wallet else True
            Clock.schedule_interval(f, 0.1)
        return wrapper

    @switch_to_send_screen
    def set_URI(self, uri):
        self.send_screen.set_URI(uri)

    def on_new_intent(self, intent):
        data = str(intent.getDataString())
        scheme = str(intent.getScheme()).lower()
        if scheme in [XAZAB_BIP21_URI_SCHEME, PAY_BIP21_URI_SCHEME]:
            self.set_URI(data)

    def on_language(self, instance, language):
        self.logger.info('language: {}'.format(language))
        _.switch_lang(language)

    def update_history(self, *dt):
        if self.history_screen:
            self.history_screen.update()

    def on_quotes(self, d):
        self.logger.info("on_quotes")
        self._trigger_update_status()
        self._trigger_update_history()

    def on_history(self, d):
        self.logger.info("on_history")
        if self.wallet:
            self.wallet.clear_coin_price_cache()
        self._trigger_update_history()

    def on_fee_histogram(self, *args):
        self._trigger_update_history()

    def on_request_status(self, event, wallet, key, status):
        req = self.wallet.receive_requests.get(key)
        if req is None:
            return
        if self.receive_screen:
            if status == PR_PAID:
                self.receive_screen.update()
            else:
                self.receive_screen.update_item(key, req)
        if self.request_popup and self.request_popup.key == key:
            self.request_popup.update_status()
        if status == PR_PAID:
            self.show_info(_('Payment Received') + '\n' + key)
            self._trigger_update_history()

    def on_invoice_status(self, event, wallet, key):
        req = self.wallet.get_invoice(key)
        if req is None:
            return
        status = self.wallet.get_invoice_status(req)
        if self.send_screen:
            if status == PR_PAID:
                self.send_screen.update()
            else:
                self.send_screen.update_item(key, req)

        if self.invoice_popup and self.invoice_popup.key == key:
            self.invoice_popup.update_status()

    def on_payment_succeeded(self, event, wallet, key):
        description = self.wallet.get_label(key)
        self.show_info(_('Payment succeeded') + '\n\n' + description)
        self._trigger_update_history()

    def on_payment_failed(self, event, wallet, key, reason):
        self.show_info(_('Payment failed') + '\n\n' + reason)

    def _get_bu(self):
        return self.electrum_config.get_base_unit()

    def _set_bu(self, value):
        self.electrum_config.set_base_unit(value)
        self._trigger_update_status()
        self._trigger_update_history()

    wallet_name = StringProperty(_('No Wallet'))
    base_unit = AliasProperty(_get_bu, _set_bu)
    fiat_unit = StringProperty('')

    def on_fiat_unit(self, a, b):
        self._trigger_update_history()

    def decimal_point(self):
        return self.electrum_config.get_decimal_point()

    def btc_to_fiat(self, amount_str):
        if not amount_str:
            return ''
        if not self.fx.is_enabled():
            return ''
        rate = self.fx.exchange_rate()
        if rate.is_nan():
            return ''
        fiat_amount = self.get_amount(amount_str + ' ' + self.base_unit) * rate / pow(10, 8)
        return "{:.2f}".format(fiat_amount).rstrip('0').rstrip('.')

    def fiat_to_btc(self, fiat_amount):
        if not fiat_amount:
            return ''
        rate = self.fx.exchange_rate()
        if rate.is_nan():
            return ''
        satoshis = int(pow(10,8) * Decimal(fiat_amount) / Decimal(rate))
        return format_satoshis_plain(satoshis, decimal_point=self.decimal_point())

    def get_amount(self, amount_str):
        a, u = amount_str.split()
        assert u == self.base_unit
        try:
            x = Decimal(a)
        except:
            return None
        p = pow(10, self.decimal_point())
        return int(p * x)


    _orientation = OptionProperty('landscape',
                                 options=('landscape', 'portrait'))

    def _get_orientation(self):
        return self._orientation

    orientation = AliasProperty(_get_orientation,
                                None,
                                bind=('_orientation',))
    '''Tries to ascertain the kind of device the app is running on.
    Cane be one of `tablet` or `phone`.

    :data:`orientation` is a read only `AliasProperty` Defaults to 'landscape'
    '''

    _ui_mode = OptionProperty('phone', options=('tablet', 'phone'))

    def _get_ui_mode(self):
        return self._ui_mode

    ui_mode = AliasProperty(_get_ui_mode,
                            None,
                            bind=('_ui_mode',))
    '''Defines tries to ascertain the kind of device the app is running on.
    Cane be one of `tablet` or `phone`.

    :data:`ui_mode` is a read only `AliasProperty` Defaults to 'phone'
    '''

    def __init__(self, **kwargs):
        self.is_android = ('ANDROID_DATA' in os.environ)
        # initialize variables
        self._clipboard = Clipboard
        self.info_bubble = None
        self.nfcscanner = None
        self.tabs = None
        self.is_exit = False
        self.wallet = None  # type: Optional[Abstract_Wallet]
        self.pause_time = 0
        self.asyncio_loop = asyncio.get_event_loop()
        self.password = None
        self._use_single_password = False
        self.resume_dialog = None

        App.__init__(self)#, **kwargs)
        Logger.__init__(self)

        self.electrum_config = config = kwargs.get('config', None)  # type: SimpleConfig
        self.language = config.get('language', 'en')
        self.network = network = kwargs.get('network', None)  # type: Network
        self.tor_auto_on_bp = self.electrum_config.get('tor_auto_on', True)
        if self.network:
            self.num_blocks = self.network.get_local_height()
            self.num_nodes = len(self.network.get_interfaces())
            net_params = self.network.get_parameters()
            self.server_host = net_params.server.host
            self.server_port = str(net_params.server.port)
            self.auto_connect = net_params.auto_connect
            self.oneserver = net_params.oneserver
            self.proxy_config = net_params.proxy if net_params.proxy else {}
            self.update_proxy_str(self.proxy_config)

        self.plugins = kwargs.get('plugins', None)  # type: Plugins
        self.gui_object = kwargs.get('gui_object', None)  # type: ElectrumGui
        self.daemon = self.gui_object.daemon
        self.fx = self.daemon.fx
        self.use_unconfirmed = not config.get('confirmed_only', False)

        # create triggers so as to minimize updating a max of 2 times a sec
        self._trigger_update_wallet = Clock.create_trigger(self.update_wallet, .5)
        self._trigger_update_status = Clock.create_trigger(self.update_status, .5)
        self._trigger_update_history = Clock.create_trigger(self.update_history, .5)
        self._trigger_update_interfaces = Clock.create_trigger(self.update_interfaces, .5)

        self._periodic_update_status_during_sync = Clock.schedule_interval(self.update_wallet_synchronizing_progress, .5)

        # cached dialogs
        self._plugins_dialog = None
        self._settings_dialog = None
        self._dash_net_dialog = None
        self._addresses_dialog = None
        self.set_fee_status()
        self.invoice_popup = None
        self.request_popup = None

    def on_pr(self, pr: 'PaymentRequest'):
        if not self.wallet:
            self.show_error(_('No wallet loaded.'))
            return
        if pr.verify(self.wallet.contacts):
            key = pr.get_id()
            invoice = self.wallet.get_invoice(key)  # FIXME wrong key...
            if invoice and self.wallet.get_invoice_status(invoice) == PR_PAID:
                self.show_error("invoice already paid")
                self.send_screen.do_clear()
            elif pr.has_expired():
                self.show_error(_('Payment request has expired'))
            else:
                self.switch_to('send')
                self.send_screen.set_request(pr)
        else:
            self.show_error("invoice error:" + pr.error)
            self.send_screen.do_clear()

    def on_qr(self, data):
        from electrum_dash.bitcoin import is_address
        data = data.strip()
        if is_address(data):
            self.set_URI(data)
            return
        data_l = data.lower()
        if (data_l.startswith(XAZAB_BIP21_URI_SCHEME + ':')
                or data_l.startswith(PAY_BIP21_URI_SCHEME + ':')):
            self.set_URI(data)
            return
        # try to decode transaction
        from electrum_dash.transaction import tx_from_any
        try:
            tx = tx_from_any(data)
        except:
            tx = None
        if tx:
            self.tx_dialog(tx)
            return
        # show error
        self.show_error("Unable to decode QR data")

    def update_tab(self, name):
        s = getattr(self, name + '_screen', None)
        if s:
            s.update()

    @profiler
    def update_tabs(self):
        for name in ['send', 'history', 'receive']:
            self.update_tab(name)

    def switch_to(self, name):
        s = getattr(self, name + '_screen', None)
        panel = self.tabs.ids.panel
        tab = self.tabs.ids[name + '_tab']
        panel.switch_to(tab)

    def show_request(self, key):
        from .uix.dialogs.request_dialog import RequestDialog
        self.request_popup = RequestDialog('Request', key)
        self.request_popup.open()

    def show_invoice(self, key):
        from .uix.dialogs.invoice_dialog import InvoiceDialog
        invoice = self.wallet.get_invoice(key)
        if not invoice:
            return
        data = key
        self.invoice_popup = InvoiceDialog('Invoice', data, key)
        self.invoice_popup.open()

    def run_other_app(self, app_name):
        if not self.is_android:
            return f'Can not start {app_name}, not android system'
        from jnius import autoclass
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        Intent = autoclass('android.content.Intent')
        pm = autoclass('android.content.pm.PackageManager')
        activity = PythonActivity.mActivity
        pm_ = activity.getPackageManager()
        array_pkg = pm_.getInstalledApplications(pm.GET_META_DATA).toArray()
        selected_pkg = []
        for i in array_pkg:
            if "/data/app/" not in getattr(i, "publicSourceDir"):
                continue
            selected_pkg.append(i)
        app_to_launch = app_name
        found = False
        for i in selected_pkg:
            if app_to_launch == getattr(i, "packageName"):
                found = True
                try:
                    package_name = getattr(i, "packageName")
                    app_intent = pm_.getLaunchIntentForPackage(package_name)
                    app_intent.setAction(Intent.ACTION_VIEW)
                    app_intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    activity.startActivity(app_intent)

                    def _run_task(activity, app_intent):
                        time.sleep(0.25)
                        activity.startActivity(app_intent)

                    args = (activity, app_intent)
                    threading.Thread(target=_run_task, args=args).start()
                except Exception as e:
                    return f'Error on lauhcing {app_name}: {str(e)}'
        if not found:
            return f'App {app_name} not found'

    def qr_dialog(self, title, data, show_text=False, text_for_clipboard=None, help_text=None):
        from .uix.dialogs.qr_dialog import QRDialog
        def on_qr_failure():
            popup.dismiss()
            msg = _('Failed to display QR code.')
            if text_for_clipboard:
                msg += '\n' + _('Text copied to clipboard.')
                self._clipboard.copy(text_for_clipboard)
            Clock.schedule_once(lambda dt: self.show_info(msg))
        popup = QRDialog(
            title, data, show_text,
            failure_cb=on_qr_failure,
            text_for_clipboard=text_for_clipboard,
            help_text=help_text)
        popup.open()

    def scan_qr(self, on_complete):
        if platform != 'android':
            return self.scan_qr_non_android(on_complete)
        from jnius import autoclass, cast
        from android import activity
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        SimpleScannerActivity = autoclass("org.dash.electrum.qr.SimpleScannerActivity")
        Intent = autoclass('android.content.Intent')
        intent = Intent(PythonActivity.mActivity, SimpleScannerActivity)

        def on_qr_result(requestCode, resultCode, intent):
            try:
                if resultCode == -1:  # RESULT_OK:
                    #  this doesn't work due to some bug in jnius:
                    # contents = intent.getStringExtra("text")
                    String = autoclass("java.lang.String")
                    contents = intent.getStringExtra(String("text"))
                    on_complete(contents)
            except Exception as e:  # exc would otherwise get lost
                send_exception_to_crash_reporter(e)
            finally:
                activity.unbind(on_activity_result=on_qr_result)
        activity.bind(on_activity_result=on_qr_result)
        PythonActivity.mActivity.startActivityForResult(intent, 0)

    def scan_qr_non_android(self, on_complete):
        from electrum_dash import qrscanner
        try:
            video_dev = self.electrum_config.get_video_device()
            data = qrscanner.scan_barcode(video_dev)
            on_complete(data)
        except UserFacingException as e:
            self.show_error(e)
        except BaseException as e:
            self.logger.exception('camera error')
            self.show_error(repr(e))

    def do_share(self, data, title):
        if platform != 'android':
            return
        from jnius import autoclass, cast
        JS = autoclass('java.lang.String')
        Intent = autoclass('android.content.Intent')
        sendIntent = Intent()
        sendIntent.setAction(Intent.ACTION_SEND)
        sendIntent.setType("text/plain")
        sendIntent.putExtra(Intent.EXTRA_TEXT, JS(data))
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        currentActivity = cast('android.app.Activity', PythonActivity.mActivity)
        it = Intent.createChooser(sendIntent, cast('java.lang.CharSequence', JS(title)))
        currentActivity.startActivity(it)

    def build(self):
        return Builder.load_file(KIVY_GUI_PATH + '/main.kv')

    def _pause(self):
        if platform == 'android':
            # move activity to back
            from jnius import autoclass
            python_act = autoclass('org.kivy.android.PythonActivity')
            mActivity = python_act.mActivity
            mActivity.moveTaskToBack(True)

    def handle_crash_on_startup(func):
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                self.logger.exception('crash on startup')
                from .uix.dialogs.crash_reporter import CrashReporter
                # show the crash reporter, and when it's closed, shutdown the app
                cr = CrashReporter(self, exctype=type(e), value=e, tb=e.__traceback__)
                cr.on_dismiss = lambda: self.stop()
                Clock.schedule_once(lambda _, cr=cr: cr.open(), 0)
        return wrapper

    @handle_crash_on_startup
    def on_start(self):
        ''' This is the start point of the kivy ui
        '''
        import time
        self.logger.info('Time to on_start: {} <<<<<<<<'.format(time.process_time()))
        Window.bind(size=self.on_size, on_keyboard=self.on_keyboard)
        #Window.softinput_mode = 'below_target'
        self.on_size(Window, Window.size)
        self.init_ui()
        crash_reporter.ExceptionHook(self)
        # init plugins
        run_hook('init_kivy', self)
        # fiat currency
        self.fiat_unit = self.fx.ccy if self.fx.is_enabled() else ''
        # default tab
        self.switch_to('history')
        # bind intent for dash: URI scheme
        if platform == 'android':
            from android import activity
            from jnius import autoclass
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            mactivity = PythonActivity.mActivity
            self.on_new_intent(mactivity.getIntent())
            activity.bind(on_new_intent=self.on_new_intent)
        # connect callbacks
        if self.network:
            interests = ['wallet_updated', 'network_updated', 'blockchain_updated',
                         'status', 'new_transaction', 'verified',
                         'verified-islock']
            util.register_callback(self.on_network_event, interests)
            util.register_callback(self.on_fee, ['fee'])
            util.register_callback(self.on_fee_histogram, ['fee_histogram'])
            util.register_callback(self.on_quotes, ['on_quotes'])
            util.register_callback(self.on_history, ['on_history'])
            util.register_callback(self.on_invoice_status, ['invoice_status'])
            util.register_callback(self.on_request_status, ['request_status'])
            util.register_callback(self.on_payment_failed, ['payment_failed'])
            util.register_callback(self.on_payment_succeeded, ['payment_succeeded'])
        # load wallet
        self.load_wallet_by_name(self.electrum_config.get_wallet_path(use_gui_last_wallet=True))
        # URI passed in config
        uri = self.electrum_config.get('url')
        if uri:
            self.set_URI(uri)

    def get_wallet_path(self):
        if self.wallet:
            return self.wallet.storage.path
        else:
            return ''

    def on_wizard_success(self, storage, db, password):
        self.password = password
        if self.electrum_config.get('single_password'):
            self._use_single_password = update_password_for_directory(self.electrum_config, password, password)
        self.logger.info(f'use single password: {self._use_single_password}')
        wallet = Wallet(db, storage, config=self.electrum_config)
        wallet.start_network(self.daemon.network)
        self.daemon.add_wallet(wallet)
        self.load_wallet(wallet)
        self.show_backup_msg()

    def show_backup_msg(self):
        w = self.wallet
        if w and getattr(w.storage, 'backup_message', None):
            WarnDialog(w.storage.backup_message, title=_('Information')).open()
            w.storage.backup_message = ''

    def on_wizard_aborted(self):
        # wizard did not return a wallet; and there is no wallet open atm
        if not self.wallet:
            self.stop()

    def load_wallet_by_name(self, path):

        def continue_load():
            self._load_wallet_by_name(path)

        if (self.electrum_config.get('tor_auto_on', True)
                and not self.network.detect_tor_proxy()):
            TorWarnDialog(self, path, continue_load).open()
        else:
            continue_load()

    def _load_wallet_by_name(self, path):
        if not path:
            return
        if self.wallet and self.wallet.storage.path == path:
            return
        if self.password and self._use_single_password:
            storage = WalletStorage(path)
            # call check_password to decrypt
            storage.check_password(self.password)
            self.on_open_wallet(self.password, storage)
            return
        d = OpenWalletDialog(self, path, self.on_open_wallet)
        d.open()

    def on_open_wallet(self, password, storage):
        if not storage.file_exists():
            wizard = InstallWizard(self.electrum_config, self.plugins)
            wizard.path = storage.path
            wizard.run('new')
        else:
            assert storage.is_past_initial_decryption()
            db = WalletDB(storage.read(), manual_upgrades=False)
            assert not db.requires_upgrade()
            if db.upgrade_done:
                storage.backup_old_version()
            if db.check_unfinished_multisig():
                wizard = InstallWizard(self.electrum_config, self.plugins)
                wizard.path = storage.path
                wizard.continue_multisig_setup(storage)
            else:
                self.on_wizard_success(storage, db, password)

    def on_stop(self):
        self.logger.info('on_stop')
        self.history_screen.stop_get_data_thread()
        self.stop_wallet()

    def stop_wallet(self):
        if self.wallet:
            util.unregister_callback(self.on_ps_callback)
            self.daemon.stop_wallet(self.wallet.storage.path)
            self.wallet = None

    def on_keyboard(self, instance, key, keycode, codepoint, modifiers):
        if key == 27 and self.is_exit is False:
            self.is_exit = True
            self.show_info(_('Press again to exit'))
            return True
        # override settings button
        if key in (319, 282): #f1/settings button on android
            #self.gui.main_gui.toggle_settings(self)
            return True

        if key == 27 and self.is_exit:
            if self.wallet:
                psman = self.wallet.psman
                is_mixing = (psman.state in psman.mixing_running_states)
                is_waiting = psman.is_waiting if is_mixing else False
                if is_mixing and not is_waiting:

                    def on_want_exit(b):
                        if b:
                            from kivy.base import stopTouchApp
                            stopTouchApp()
                    d = Question(psman.WAIT_MIXING_STOP_MSG, on_want_exit)
                    d.open()
                    return True

    def settings_dialog(self):
        from .uix.dialogs.settings import SettingsDialog
        if self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)
        self._settings_dialog.update()
        self._settings_dialog.open()

    def is_wallet_creation_disabled(self):
        return bool(self.electrum_config.get('single_password')) and self.password is None

    def wallets_dialog(self):
        from .uix.dialogs.wallets import WalletDialog
        dirname = os.path.dirname(self.electrum_config.get_wallet_path())
        d = WalletDialog(dirname, self.load_wallet_by_name, self.is_wallet_creation_disabled())
        d.open()

    def plugins_dialog(self):
        from .uix.dialogs.plugins import PluginsDialog
        if self._plugins_dialog is None:
            self._plugins_dialog = PluginsDialog(self)
        self._plugins_dialog.update()
        self._plugins_dialog.open()

    def dash_net_dialog(self):
        from .uix.dialogs.dash_net import XazabNetDialog
        if self._dash_net_dialog is None:
            self._dash_net_dialog = XazabNetDialog(self)
        self._dash_net_dialog.update()
        self._dash_net_dialog.open()

    def privatesend_dialog(self):
        if self.wallet.psman.unsupported:
            from .uix.dialogs.privatesend import PSDialogUnsupportedPS as psdlg
        else:
            from .uix.dialogs.privatesend import PSDialog as psdlg
        psdlg(self).open()

    def popup_dialog(self, name):
        if name == 'settings':
            self.settings_dialog()
        elif name == 'plugins':
            self.plugins_dialog()
        elif name == 'dash_net':
            self.dash_net_dialog()
        elif name == 'privatesend':
            self.privatesend_dialog()
        elif name == 'wallets':
            self.wallets_dialog()
        elif name == 'status':
            popup = Builder.load_file(KIVY_GUI_PATH + f'/uix/ui_screens/{name}.kv')
            master_public_keys_layout = popup.ids.master_public_keys
            for xpub in self.wallet.get_master_public_keys()[1:]:
                master_public_keys_layout.add_widget(TopLabel(text=_('Master Public Key')))
                ref = RefLabel()
                ref.name = _('Master Public Key')
                ref.data = xpub
                master_public_keys_layout.add_widget(ref)
            popup.open()
        elif name.endswith("_dialog"):
            getattr(self, name)()
        else:
            popup = Builder.load_file(KIVY_GUI_PATH + f'/uix/ui_screens/{name}.kv')
            popup.open()

    @profiler
    def init_ui(self):
        ''' Initialize The Ux part of electrum. This function performs the basic
        tasks of setting up the ui.
        '''
        #from weakref import ref

        self.funds_error = False
        # setup UX
        self.screens = {}

        #setup lazy imports for mainscreen
        Factory.register('AnimatedPopup',
                         module='electrum_dash.gui.kivy.uix.dialogs')
        Factory.register('QRCodeWidget',
                         module='electrum_dash.gui.kivy.uix.qrcodewidget')

        # preload widgets. Remove this if you want to load the widgets on demand
        #Cache.append('electrum_dash_widgets', 'AnimatedPopup', Factory.AnimatedPopup())
        #Cache.append('electrum_dash_widgets', 'QRCodeWidget', Factory.QRCodeWidget())

        # load and focus the ui
        self.root.manager = self.root.ids['manager']

        self.history_screen = None
        self.send_screen = None
        self.receive_screen = None
        if self.testnet:
            self.icon = os.path.dirname(KIVY_GUI_PATH) + "/icons/electrum-dash-testnet.png"
        else:
            self.icon = os.path.dirname(KIVY_GUI_PATH) + "/icons/electrum-dash.png"
        self.root.ids.ps_button.icon = self.ps_icon()
        self.tabs = self.root.ids['tabs']

    def update_interfaces(self, dt):
        net_params = self.network.get_parameters()
        self.num_nodes = len(self.network.get_interfaces())
        self.num_chains = len(self.network.get_blockchains())
        chain = self.network.blockchain()
        self.blockchain_forkpoint = chain.get_max_forkpoint()
        self.blockchain_name = chain.get_name()
        interface = self.network.interface
        if interface:
            self.server_host = interface.host
        else:
            self.server_host = str(net_params.server.host) + ' (connecting...)'
        self.proxy_config = net_params.proxy or {}
        self.update_proxy_str(self.proxy_config)

    def on_network_event(self, event, *args):
        self.logger.info('network event: '+ event)
        if event == 'network_updated':
            self._trigger_update_interfaces()
            self._trigger_update_status()
        elif event == 'wallet_updated':
            self._trigger_update_wallet()
            self._trigger_update_status()
        elif event == 'blockchain_updated':
            # to update number of confirmations in history
            self._trigger_update_wallet()
        elif event == 'status':
            self._trigger_update_status()
        elif event == 'new_transaction':
            wallet, tx = args
            if wallet.psman.need_notify(tx.txid()):
                self._trigger_update_wallet()
        elif event == 'verified':
            self._trigger_update_wallet()
        elif event == 'verified-islock':
            self._trigger_update_wallet()

    def on_ps_callback(self, event, *args):
        Clock.schedule_once(lambda dt: self.on_ps_event(event, *args))

    def on_ps_event(self, event, *args):
        psman = self.wallet.psman
        is_mixing = (psman.state in psman.mixing_running_states)
        is_waiting = psman.is_waiting if is_mixing else False
        if event == 'ps-data-changes':
            wallet = args[0]
            if wallet == self.wallet:
                self._trigger_update_wallet()
        if event == 'ps-reserved-changes':
            wallet = args[0]
            if wallet == self.wallet:
                self._trigger_update_wallet()
        elif event in ['ps-state-changes', 'ps-wfl-changes',
                       'ps-keypairs-changes']:
            wallet, msg, msg_type = (*args, None, None)[:3]
            if wallet == self.wallet:
                self.update_ps_btn(is_mixing, is_waiting)
                if msg:
                    if msg_type and msg_type.startswith('inf'):
                        self.show_info(msg)
                    else:
                        WarnDialog(msg, title=_('PrivateSend')).open()
        elif event == 'ps-not-enough-sm-denoms':
            wallet, denoms_by_vals = args
            if wallet == self.wallet:
                q = psman.create_sm_denoms_data(confirm_txt=True)

                def create_small_denoms(confirmed):
                    if confirmed:
                        self.create_small_denoms(denoms_by_vals)

                d = Question(q, create_small_denoms)
                d.open()
        elif event == 'ps-other-coins-arrived':
            wallet, txid = args
            if wallet == self.wallet:
                q = '\n\n'.join([psman.OTHER_COINS_ARRIVED_MSG1.format(txid),
                                 psman.OTHER_COINS_ARRIVED_MSG2,
                                 psman.OTHER_COINS_ARRIVED_MSG3,
                                 psman.OTHER_COINS_ARRIVED_MSG4,
                                 psman.OTHER_COINS_ARRIVED_Q])

                def show_coins_dialog(confirmed):
                    if confirmed:
                        self.coins_dialog(1)

                d = Question(q, show_coins_dialog)
                d.open()

    def create_small_denoms(self, denoms_by_vals):
        w = self.wallet
        psman = w.psman
        coins = psman.get_biggest_denoms_by_min_round()
        if not coins:
            msg = psman.create_sm_denoms_data(no_denoms_txt=True)
            self.show_error(msg)
        self.create_new_denoms(coins[0:1])

    def create_new_denoms(self, coins):
        def on_q_answered(confirmed):
            if confirmed:
                self.protected(_('Enter your PIN code to sign'
                                 ' new denoms transactions'),
                               self._create_new_denoms, (coins,))

        w = self.wallet
        psman = w.psman
        info = psman.new_denoms_from_coins_info(coins)
        q = _('Do you want to create transactions?\n\n{}').format(info)
        d = Question(q, on_q_answered)
        d.open()

    def _create_new_denoms(self, coins, password):
        w = self.wallet
        psman = w.psman
        wfl, err = psman.create_new_denoms_wfl_from_gui(coins, password)
        if err:
            self.show_error(err)
        else:
            self.show_info(f'Created New Denoms workflow with'
                           f' txids: {", ".join(wfl.tx_order)}')

    def create_new_collateral(self, coins):
        def on_q_answered(confirmed):
            if confirmed:
                self.protected(_('Enter your PIN code to sign'
                                 ' new collateral transactions'),
                               self._create_new_collateral, (coins,))

        w = self.wallet
        psman = w.psman
        info = psman.new_collateral_from_coins_info(coins)
        q = _('Do you want to create transactions?\n\n{}').format(info)
        d = Question(q, on_q_answered)
        d.open()

    def _create_new_collateral(self, coins, password):
        w = self.wallet
        psman = w.psman
        wfl, err = psman.create_new_collateral_wfl_from_gui(coins, password)
        if err:
            self.show_error(err)
        else:
            self.show_info(f'Created New Collateral workflow with'
                           f' txids: {", ".join(wfl.tx_order)}')

    def update_ps_btn(self, is_mixing, is_waiting):
        ps_button = self.root.ids.ps_button
        ps_button.icon = self.ps_icon(active=is_mixing, is_waiting=is_waiting)

    @profiler
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        if self.wallet:
            self.stop_wallet()
        self.wallet = wallet
        util.register_callback(self.on_ps_callback,
                               ['ps-data-changes',
                                'ps-reserved-changes',
                                'ps-not-enough-sm-denoms',
                                'ps-other-coins-arrived',
                                'ps-wfl-changes',
                                'ps-keypairs-changes',
                                'ps-state-changes'])
        self.wallet_name = wallet.basename()
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something
        # since the callback has been called before the GUI was initialized
        if self.receive_screen:
            self.receive_screen.clear()
        self.update_tabs()
        run_hook('load_wallet', wallet, self)
        try:
            wallet.try_detecting_internal_addresses_corruption()
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            send_exception_to_crash_reporter(e)
            return
        self.use_change = self.wallet.use_change
        self.electrum_config.save_last_wallet(wallet)
        self.request_focus_for_main_view()

    def request_focus_for_main_view(self):
        if platform != 'android':
            return
        # The main view of the activity might be not have focus
        # in which case e.g. the OS "back" button would not work.
        # see #6276 (specifically "method 2" and "method 3")
        from jnius import autoclass
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        PythonActivity.requestFocusForMainView()

    def update_status(self, *dt):
        if not self.wallet:
            return
        if self.network is None or not self.network.is_connected():
            status = _("Offline")
        elif self.network.is_connected():
            self.num_blocks = self.network.get_local_height()
            server_height = self.network.get_server_height()
            server_lag = self.num_blocks - server_height
            if not self.wallet.up_to_date or server_height == 0:
                num_sent, num_answered = self.wallet.get_history_sync_state_details()
                status = ("{} [size=18dp]({}/{})[/size]"
                          .format(_("Synchronizing..."), num_answered, num_sent))
            elif server_lag > 1:
                status = _("Server is lagging ({} blocks)").format(server_lag)
            else:
                status = ''
        else:
            status = _("Disconnected")
        if status:
            self.balance = status
            self.fiat_balance = status
        else:
            c, u, x = self.wallet.get_balance()
            balance_sat = c + u + x
            text = self.format_amount(balance_sat)
            self.balance = str(text.strip()) + ' [size=22dp]%s[/size]'% self.base_unit
            self.fiat_balance = self.fx.format_amount(balance_sat) + ' [size=22dp]%s[/size]'% self.fx.ccy

    def update_wallet_synchronizing_progress(self, *dt):
        if not self.wallet:
            return
        if not self.wallet.up_to_date:
            self._trigger_update_status()

    def get_max_amount(self, is_ps=False):
        from electrum_dash.transaction import PartialTxOutput
        if run_hook('abort_send', self):
            return ''
        min_rounds = None if not is_ps else self.wallet.psman.mix_rounds
        include_ps = (min_rounds is None)
        inputs = self.wallet.get_spendable_coins(None,
                                                 include_ps=include_ps,
                                                 min_rounds=min_rounds)
        if not inputs:
            return ''
        addr = None
        if self.send_screen:
            addr = str(self.send_screen.address)
        if not addr:
            addr = self.wallet.dummy_address()
        outputs = [PartialTxOutput.from_address_and_value(addr, '!')]
        try:
            tx = self.wallet.make_unsigned_transaction(coins=inputs, outputs=outputs,
                                                       min_rounds=min_rounds)
        except NoDynamicFeeEstimates as e:
            Clock.schedule_once(lambda dt, bound_e=e: self.show_error(str(bound_e)))
            return ''
        except NotEnoughFunds:
            return ''
        except InternalAddressCorruption as e:
            self.show_error(str(e))
            send_exception_to_crash_reporter(e)
            return ''
        amount = tx.output_value()
        __, x_fee_amount = run_hook('get_tx_extra_fee', self.wallet, tx) or (None, 0)
        amount_after_all_fees = amount - x_fee_amount
        return format_satoshis_plain(amount_after_all_fees, decimal_point=self.decimal_point())

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(
            x,
            num_zeros=0,
            decimal_point=self.decimal_point(),
            is_diff=is_diff,
            whitespaces=whitespaces,
        )

    def format_amount_and_units(self, x) -> str:
        if x is None:
            return 'none'
        if x == '!':
            return 'max'
        return format_satoshis_plain(x, decimal_point=self.decimal_point()) + ' ' + self.base_unit

    def format_fee_rate(self, fee_rate):
        # fee_rate is in duffs/kB
        return format_fee_satoshis(fee_rate) + ' duffs/kB'

    #@profiler
    def update_wallet(self, *dt):
        self._trigger_update_status()
        if self.wallet and (self.wallet.up_to_date or not self.network or not self.network.is_connected()):
            self.update_tabs()

    def notify(self, message):
        try:
            global notification, os
            if not notification:
                from plyer import notification
            icon = (os.path.dirname(os.path.realpath(__file__))
                    + '/../../' + self.icon)
            notification.notify('Xazab Electrum', message,
                            app_icon=icon, app_name='Xazab Electrum')
        except ImportError:
            self.logger.Error('Notification: needs plyer; `sudo python3 -m pip install plyer`')

    @property
    def testnet(self):
        return self.electrum_config.get('testnet')

    @property
    def app_icon(self):
        return ATLAS_ICON % ('logo-testnet' if self.testnet else 'logo')

    def ps_icon(self, active=False, is_waiting=False):
        if not active:
            icon = 'privatesend'
        elif not is_waiting:
            icon = 'privatesend_active'
        else:
            icon = 'privatesend_waiting'
        return ATLAS_ICON % icon

    def on_pause(self):
        self.pause_time = time.time()
        # pause nfc
        if self.nfcscanner:
            self.nfcscanner.nfc_disable()
        return True

    def on_resume(self):
        if self.nfcscanner:
            self.nfcscanner.nfc_enable()
        if self.resume_dialog is not None:
            return
        now = time.time()
        if self.wallet and self.has_pin_code() and now - self.pause_time > 5*60:
            def on_success(x):
                self.resume_dialog = None
            d = PincodeDialog(
                self,
                check_password=self.check_pin_code,
                on_success=on_success,
                on_failure=self.stop)
            self.resume_dialog = d
            d.open()

    def on_size(self, instance, value):
        width, height = value
        self._orientation = 'landscape' if width > height else 'portrait'
        self._ui_mode = 'tablet' if min(width, height) > inch(3.51) else 'phone'

    def on_ref_label(self, label, *, show_text_with_qr: bool = True):
        if not label.data:
            return
        self.qr_dialog(label.name, label.data, show_text_with_qr)

    def show_error(self, error, width='200dp', pos=None, arrow_pos=None,
                   exit=False, icon=f'atlas://{KIVY_GUI_PATH}/theming/light/error', duration=0,
                   modal=False):
        ''' Show an error Message Bubble.
        '''
        self.show_info_bubble(text=error, icon=icon, width=width,
            pos=pos or Window.center, arrow_pos=arrow_pos, exit=exit,
            duration=duration, modal=modal)

    def show_info(self, error, width='200dp', pos=None, arrow_pos=None,
                  exit=False, duration=0, modal=False):
        ''' Show an Info Message Bubble.
        '''
        self.show_error(error, icon=f'atlas://{KIVY_GUI_PATH}/theming/light/important',
            duration=duration, modal=modal, exit=exit, pos=pos,
            arrow_pos=arrow_pos)

    def show_info_bubble(self, text=_('Hello World'), pos=None, duration=0,
                         arrow_pos='bottom_mid', width=None, icon='', modal=False, exit=False):
        '''Method to show an Information Bubble

        .. parameters::
            text: Message to be displayed
            pos: position for the bubble
            duration: duration the bubble remains on screen. 0 = click to hide
            width: width of the Bubble
            arrow_pos: arrow position for the bubble
        '''
        text = str(text)  # so that we also handle e.g. Exception
        info_bubble = self.info_bubble
        if not info_bubble:
            info_bubble = self.info_bubble = Factory.InfoBubble()

        win = Window
        if info_bubble.parent:
            win.remove_widget(info_bubble
                                 if not info_bubble.modal else
                                 info_bubble._modal_view)

        if not arrow_pos:
            info_bubble.show_arrow = False
        else:
            info_bubble.show_arrow = True
            info_bubble.arrow_pos = arrow_pos
        img = info_bubble.ids.img
        if text == 'texture':
            # icon holds a texture not a source image
            # display the texture in full screen
            text = ''
            img.texture = icon
            info_bubble.fs = True
            info_bubble.show_arrow = False
            img.allow_stretch = True
            info_bubble.dim_background = True
            info_bubble.background_image = f'atlas://{KIVY_GUI_PATH}/theming/light/card'
        else:
            info_bubble.fs = False
            info_bubble.icon = icon
            #if img.texture and img._coreimage:
            #    img.reload()
            img.allow_stretch = False
            info_bubble.dim_background = False
            info_bubble.background_image = 'atlas://data/images/defaulttheme/bubble'
        info_bubble.message = text
        if not pos:
            pos = (win.center[0], win.center[1] - (info_bubble.height/2))
        info_bubble.show(pos, duration, width, modal=modal, exit=exit)

    def tx_dialog(self, tx):
        from .uix.dialogs.tx_dialog import TxDialog
        d = TxDialog(self, tx)
        d.open()

    def show_transaction(self, txid):
        tx = self.wallet.db.get_transaction(txid)
        if tx:
            self.tx_dialog(tx)
        else:
            self.show_error(f'Transaction not found {txid}')

    def sign_tx(self, *args):
        threading.Thread(target=self._sign_tx, args=args).start()

    def _sign_tx(self, tx, password, on_success, on_failure):
        try:
            self.wallet.sign_transaction(tx, password)
        except InvalidPassword:
            Clock.schedule_once(lambda dt: on_failure(_("Invalid PIN")))
            return
        on_success = run_hook('tc_sign_wrapper', self.wallet, tx, on_success, on_failure) or on_success
        Clock.schedule_once(lambda dt: on_success(tx))

    def _broadcast_thread(self, tx, pr, on_complete):
        status = False
        if pr and pr.has_expired():
            self.send_screen.payment_request = None
            status, msg = False, _("Invoice has expired")
            Clock.schedule_once(lambda dt: on_complete(status, msg))
            return
        need_broadcast = True if not pr or pr.need_broadcast_tx else False
        txid = tx.txid()
        try:
            if need_broadcast:
                coro = self.wallet.psman.broadcast_transaction(tx)
                self.network.run_from_another_thread(coro)
            else:
                self.logger.info(f'Do not broadcast: {txid}, send bip70'
                                 f' Payment msg to: {pr.payment_url}')
        except TxBroadcastError as e:
            msg = e.get_message_for_gui()
        except PSPossibleDoubleSpendError as e:
            msg = str(e)
        except PSSpendToPSAddressesError as e:
            msg = str(e)
        except BestEffortRequestFailed as e:
            msg = repr(e)
        else:
            if pr:
                self.send_screen.payment_request = None
                refund_address = self.wallet.get_receiving_address()
                coro = pr.send_payment_and_receive_paymentack(tx.serialize(), refund_address)
                fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
                ack_status, ack_msg = fut.result(timeout=20)
                self.logger.info(f"Payment ACK: {ack_status}. Ack message: {ack_msg}")
            if need_broadcast:
                status, msg = True, txid
            else:
                status, msg = ack_status, ack_msg
        Clock.schedule_once(lambda dt: on_complete(status, msg))

    def broadcast(self, tx, pr=None):
        def on_complete(ok, msg):
            if ok:
                self.show_info(_('Payment sent.'))
                if self.send_screen:
                    self.send_screen.do_clear()
            else:
                msg = msg or ''
                self.show_error(msg)

        if self.network and self.network.is_connected():
            self.show_info(_('Sending'))
            threading.Thread(target=self._broadcast_thread, args=(tx, pr, on_complete)).start()
        else:
            self.show_info(_('Cannot broadcast transaction') +
                           ':\n' + _('Electrum network not connected'))

    def description_dialog(self, screen):
        from .uix.dialogs.label_dialog import LabelDialog
        text = screen.message
        def callback(text):
            screen.message = text
        d = LabelDialog(_('Enter description'), text, callback)
        d.open()

    def amount_dialog(self, screen, show_max):
        from .uix.dialogs.amount_dialog import AmountDialog
        amount = screen.amount
        if amount:
            amount, u = str(amount).split()
            assert u == self.base_unit
        is_ps = getattr(screen, 'is_ps', None)
        def amount_cb(amount):
            if amount == '!':
                screen.is_max = True
                max_amt = self.get_max_amount()
                screen.amount = (max_amt + ' ' + self.base_unit) if max_amt else ''
            else:
                screen.amount = amount
                screen.is_max = False
        if is_ps is None:
            popup = AmountDialog(show_max, amount, cb=amount_cb)
        else:
            popup = AmountDialog(show_max, amount, is_ps=is_ps, cb=amount_cb)
        popup.open()

    def addresses_dialog(self):
        from .uix.dialogs.addresses import AddressesDialog
        if self._addresses_dialog is None:
            self._addresses_dialog = AddressesDialog(self)
        self._addresses_dialog.update()
        self._addresses_dialog.open()

    def coins_dialog(self, filter_val=0):
        from .uix.dialogs.coins_dialog import CoinsDialog
        popup = CoinsDialog(self, filter_val=filter_val)
        popup.update()
        popup.open()

    def fee_dialog(self):
        from .uix.dialogs.fee_dialog import FeeDialog
        fee_dialog = FeeDialog(self, self.electrum_config, self.set_fee_status)
        fee_dialog.open()

    def set_fee_status(self):
        target, tooltip, dyn = self.electrum_config.get_fee_target()
        self.fee_status = target

    def on_fee(self, event, *arg):
        self.set_fee_status()

    def protected(self, msg, f, args):
        if self.electrum_config.get('pin_code'):
            msg += "\n" + _("Enter your PIN code to proceed")
            on_success = lambda pw: f(*args, self.password)
            d = PincodeDialog(
                self,
                message = msg,
                check_password=self.check_pin_code,
                on_success=on_success,
                on_failure=lambda: None)
            d.open()
        else:
            d = Question(
                msg,
                lambda b: f(*args, self.password) if b else None,
                yes_str=_("OK"),
                no_str=_("Cancel"),
                title=_("Confirm action"))
            d.open()

    def delete_wallet(self):
        basename = os.path.basename(self.wallet.storage.path)
        d = Question(_('Delete wallet?') + '\n' + basename, self._delete_wallet)
        d.open()

    def _delete_wallet(self, b):
        if b:
            basename = self.wallet.basename()
            self.protected(_("Are you sure you want to delete wallet {}?").format(basename),
                           self.__delete_wallet, ())

    def __delete_wallet(self, pw):
        wallet_path = self.get_wallet_path()
        basename = os.path.basename(wallet_path)
        if self.wallet.has_password():
            try:
                self.wallet.check_password(pw)
            except InvalidPassword:
                self.show_error("Invalid password")
                return
        self.stop_wallet()
        os.unlink(wallet_path)
        self.show_error(_("Wallet removed: {}").format(basename))
        new_path = self.electrum_config.get_wallet_path(use_gui_last_wallet=True)
        self.load_wallet_by_name(new_path)

    def show_seed(self, label):
        self.protected(_("Display your seed?"), self._show_seed, (label,))

    def _show_seed(self, label, password):
        if self.wallet.has_password() and password is None:
            return
        keystore = self.wallet.keystore
        seed = keystore.get_seed(password)
        passphrase = keystore.get_passphrase(password)
        label.data = seed
        if passphrase:
            label.data += '\n\n' + _('Passphrase') + ': ' + passphrase

    def has_pin_code(self):
        return bool(self.electrum_config.get('pin_code'))

    def check_pin_code(self, pin):
        if pin != self.electrum_config.get('pin_code'):
            raise InvalidPassword

    def change_password(self, cb):
        def on_success(old_password, new_password):
            # called if old_password works on self.wallet
            self.password = new_password
            if self._use_single_password:
                path = self.wallet.storage.path
                self.stop_wallet()
                update_password_for_directory(self.electrum_config, old_password, new_password)
                self.load_wallet_by_name(path)
                msg = _("Password updated successfully")
            else:
                self.wallet.update_password(old_password, new_password)
                msg = _("Password updated for {}").format(os.path.basename(self.wallet.storage.path))
            self.show_info(msg)
        on_failure = lambda: self.show_error(_("Password not updated"))
        d = ChangePasswordDialog(self, self.wallet, on_success, on_failure)
        d.open()

    def pin_code_dialog(self, cb):
        if self._use_single_password and self.has_pin_code():
            def on_choice(choice):
                if choice == 0:
                    self.change_pin_code(cb)
                else:
                    self.reset_pin_code(cb)
            choices = {0:'Change PIN code', 1:'Reset PIN'}
            dialog = ChoiceDialog(
                _('PIN Code'), choices, 0,
                on_choice,
                keep_choice_order=True)
            dialog.open()
        else:
            self.change_pin_code(cb)

    def reset_pin_code(self, cb):
        on_success = lambda x: self._set_new_pin_code(None, cb)
        d = PasswordDialog(self,
            basename = self.wallet.basename(),
            check_password = self.wallet.check_password,
            on_success=on_success,
            on_failure=lambda: None,
            is_change=False,
            has_password=self.wallet.has_password())
        d.open()

    def _set_new_pin_code(self, new_pin, cb):
        self.electrum_config.set_key('pin_code', new_pin)
        cb()
        self.show_info(_("PIN updated") if new_pin else _('PIN disabled'))

    def change_pin_code(self, cb):
        on_failure = lambda: self.show_error(_("PIN not updated"))
        on_success = lambda old_pin, new_pin: self._set_new_pin_code(new_pin, cb)
        d = PincodeDialog(
            self,
            check_password=self.check_pin_code,
            on_success=on_success,
            on_failure=on_failure,
            is_change=True,
            has_password = self.has_pin_code())
        d.open()

    def save_backup(self):
        if platform != 'android':
            backup_dir = self.electrum_config.get_backup_dir()
            if backup_dir:
                self._save_backup(backup_dir)
            else:
                self.show_error(_("Backup NOT saved. Backup directory not configured."))
            return

        backup_dir = util.android_backup_dir()
        from android.permissions import request_permissions, Permission
        def cb(permissions, grant_results: Sequence[bool]):
            if not grant_results or not grant_results[0]:
                self.show_error(_("Cannot save backup without STORAGE permission"))
                return
            # note: Clock.schedule_once is a hack so that we get called on a non-daemon thread
            #       (needed for WalletDB.write)
            Clock.schedule_once(lambda dt: self._save_backup(backup_dir))
        request_permissions([Permission.WRITE_EXTERNAL_STORAGE], cb)

    def _save_backup(self, backup_dir):
        try:
            new_path = self.wallet.save_backup(backup_dir)
        except Exception as e:
            self.logger.exception("Failed to save wallet backup")
            self.show_error("Failed to save wallet backup" + '\n' + str(e))
            return
        self.show_info(_("Backup saved:") + f"\n{new_path}")

    def export_private_keys(self, pk_label, addr):
        if self.wallet.is_watching_only():
            self.show_info(_('This is a watching-only wallet. It does not contain private keys.'))
            return
        def show_private_key(addr, pk_label, password):
            if self.wallet.has_password() and password is None:
                return
            if not self.wallet.can_export():
                return
            try:
                key = str(self.wallet.export_private_key(addr, password))
                pk_label.data = key
            except InvalidPassword:
                self.show_error("Invalid PIN")
                return
        self.protected(_("Decrypt your private key?"), show_private_key, (addr, pk_label))
