"""Главное окно DroidScout."""

import datetime
import os
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSizePolicy, QSplitter,
    QStatusBar, QTabWidget, QTableView, QToolBar, QToolButton, QVBoxLayout,
    QWidget, QHeaderView, QAbstractItemView)

from .. import __version__, APP_NAME, adb_actions, adb_info, config, exporter, i18n, netprobe, scanner, storage
from .. import fingerprint
from ..fingerprint import Device, type_label, verdict_label
from .device_model import DeviceModel
from .adb_toolkit import AdbToolkitDialog
from .deep_scan import DeepScanDialog
from .dialogs import (AdbInstallDialog, AdbQueryWorker, SettingsDialog,
                      UpdateDialog, UpdateWorker)
from .theme import apply_theme, app_icon, theme_bg


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        i18n.set_language(i18n.detect_language())
        self.engine = None
        self.update_worker = None
        self.scan_started = 0.0
        self._last_scan_devices = []

        self.setWindowTitle(i18n.tr("app_title"))
        self.setWindowIcon(app_icon())
        self.resize(1180, 720)

        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        storage.init()
        self._refresh_history()

    # ------------------------------------------------------------- интерфейс
    def _build_menu(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu(i18n.tr("menu_file"))
        exit_action = file_menu.addAction(i18n.tr("menu_exit"))
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)

        help_menu = menu_bar.addMenu(i18n.tr("menu_help"))
        about_action = help_menu.addAction(i18n.tr("menu_about"))
        about_action.triggered.connect(self._show_about)

    def _build_toolbar(self):
        toolbar = QToolBar("main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.scan_btn = QToolButton()
        self.scan_btn.setText(i18n.tr("scan"))
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)
        toolbar.addWidget(self.scan_btn)

        self.stop_btn = QToolButton()
        self.stop_btn.setText(i18n.tr("scan_stop"))
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        toolbar.addWidget(self.stop_btn)
        toolbar.addSeparator()

        self.net_label = QLabel(i18n.tr("network"))
        toolbar.addWidget(self.net_label)
        self.net_combo = QComboBox()
        self.net_combo.setMinimumWidth(230)
        self._fill_networks()
        toolbar.addWidget(self.net_combo)
        toolbar.addSeparator()

        self.export_btn = QToolButton()
        self.export_btn.setText(i18n.tr("export"))
        menu = QMenu(self.export_btn)
        self.csv_action = menu.addAction(i18n.tr("export_csv"))
        self.json_action = menu.addAction(i18n.tr("export_json"))
        self.csv_action.triggered.connect(lambda: self._export("csv"))
        self.json_action.triggered.connect(lambda: self._export("json"))
        self.export_btn.setMenu(menu)
        toolbar.addWidget(self.export_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.theme_btn = QToolButton()
        self.theme_btn.setText(i18n.tr("theme_dark") + " / " + i18n.tr("theme_light"))
        self.theme_btn.clicked.connect(self.toggle_theme)
        toolbar.addWidget(self.theme_btn)

        self.lang_btn = QToolButton()
        self.lang_btn.setText("RU / EN")
        self.lang_btn.clicked.connect(self.toggle_language)
        toolbar.addWidget(self.lang_btn)

        self.update_btn = QToolButton()
        self.update_btn.setText(i18n.tr("check_updates"))
        self.update_btn.clicked.connect(self.check_updates_manual)
        toolbar.addWidget(self.update_btn)

        self.settings_btn = QToolButton()
        self.settings_btn.setText(i18n.tr("settings"))
        self.settings_btn.clicked.connect(self.open_settings)
        toolbar.addWidget(self.settings_btn)

        QShortcut(QKeySequence("F5"), self, activated=self.start_scan)

    def _build_central(self):
        tabs = QTabWidget()
        self._paint_bg(tabs)
        self._paint_bg(tabs.tabBar())
        self.setCentralWidget(tabs)

        # ---- Вкладка сканирования -----------------------------------------
        scan_page = QWidget()
        scan_layout = QVBoxLayout(scan_page)
        scan_layout.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Vertical)
        self.table = QTableView()
        self.model = DeviceModel(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.resizeSection(0, 130)   # ip
        header.resizeSection(1, 150)   # mac
        header.resizeSection(2, 170)   # vendor
        header.resizeSection(3, 160)   # hostname
        header.resizeSection(4, 150)   # type
        header.resizeSection(5, 150)   # model
        header.resizeSection(6, 150)   # manufacturer
        header.resizeSection(7, 90)    # confidence
        header.resizeSection(8, 150)   # ports
        header.resizeSection(9, 140)   # services
        header.resizeSection(10, 80)   # status
        self.table.setSortingEnabled(True)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self.table)

        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 4, 0, 0)
        self.details_title = QLabel(i18n.tr("device_details"))
        font = QFont()
        font.setBold(True)
        self.details_title.setFont(font)
        details_layout.addWidget(self.details_title)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(190)
        self.details.setPlainText(i18n.tr("details_none"))
        details_layout.addWidget(self.details)
        btn_grid = QGridLayout()
        btn_grid.setContentsMargins(0, 0, 0, 0)
        self.adb_btn = QPushButton(i18n.tr("adb_details"))
        self.adb_btn.clicked.connect(self.query_adb)
        btn_grid.addWidget(self.adb_btn, 0, 0)
        self.toolkit_btn = QPushButton(i18n.tr("adb_toolkit_btn"))
        self.toolkit_btn.clicked.connect(self.open_toolkit)
        btn_grid.addWidget(self.toolkit_btn, 0, 1)
        self.deepscan_btn = QPushButton(i18n.tr("deepscan_btn"))
        self.deepscan_btn.clicked.connect(self.open_deep_scan)
        btn_grid.addWidget(self.deepscan_btn, 0, 2)
        self.wol_btn = QPushButton(i18n.tr("wol_btn"))
        self.wol_btn.clicked.connect(self.wake_device)
        btn_grid.addWidget(self.wol_btn, 1, 0)
        self.copy_btn = QPushButton(i18n.tr("copy_info"))
        self.copy_btn.clicked.connect(self.copy_details)
        btn_grid.addWidget(self.copy_btn, 1, 1)
        details_layout.addLayout(btn_grid)
        splitter.addWidget(details_widget)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)

        scan_layout.addWidget(splitter)
        tabs.addTab(scan_page, i18n.tr("tab_scan"))

        # ---- Вкладка истории ------------------------------------------------
        history_page = QWidget()
        history_layout = QVBoxLayout(history_page)
        history_layout.setContentsMargins(8, 8, 8, 8)

        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(180)
        self.history_list.itemSelectionChanged.connect(self._on_history_pick)
        history_layout.addWidget(self.history_list)

        self.history_table = QTableView()
        self.history_model = DeviceModel(self)
        self.history_table.setModel(self.history_model)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setSortingEnabled(True)
        history_layout.addWidget(self.history_table)

        clear_row = QHBoxLayout()
        self.clear_history_btn = QPushButton(i18n.tr("history_delete"))
        self.clear_history_btn.clicked.connect(self._clear_history)
        clear_row.addWidget(self.clear_history_btn)
        clear_row.addStretch(1)
        history_layout.addLayout(clear_row)
        tabs.addTab(history_page, i18n.tr("tab_history"))

        self.tabs = tabs

    def _paint_bg(self, widget):
        """Закрашивает виджет цветом фона темы (QTabWidget/QTabBar не красят
        свой фон через QSS на части платформ)."""
        from PySide6.QtGui import QColor, QPalette
        widget.setAutoFillBackground(True)
        palette = widget.palette()
        palette.setColor(QPalette.Window, QColor(theme_bg()))
        widget.setPalette(palette)

    def _build_statusbar(self):
        status = QStatusBar()
        self.setStatusBar(status)
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(260)
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        status.addPermanentWidget(self.progress)
        self.status_label = QLabel(i18n.tr("ready"))
        status.addWidget(self.status_label)
        self.counts_label = QLabel("")
        status.addPermanentWidget(self.counts_label)

    # ------------------------------------------------------------- вспомогательное
    def _fill_networks(self):
        self.net_combo.clear()
        networks = scanner.local_networks()
        if not networks:
            self.net_combo.addItem(i18n.tr("no_networks"), "")
            return
        for nic, net in networks:
            self.net_combo.addItem(f"{net}  ({nic})", net)
        if len(networks) > 1:
            self.net_combo.addItem(i18n.tr("net_all"), "|".join(net for _nic, net in networks))

    def _show_about(self):
        QMessageBox.about(self, i18n.tr("menu_about"),
                          i18n.tr("about_text", version=__version__))

    def after_start(self):
        """Вызывается после show(): авто-проверка обновлений."""
        if config.get("check_updates_on_start", True):
            QTimer.singleShot(800, self.check_updates_silent)

    # ------------------------------------------------------------- сканирование
    def start_scan(self):
        if self.engine:
            return
        net = self.net_combo.currentData()
        if not net:
            self._fill_networks()
            net = self.net_combo.currentData()
            if not net:
                QMessageBox.warning(self, i18n.tr("err_title"), i18n.tr("no_networks"))
                return
        networks = net.split("|")
        self.model.set_devices([])
        self.details.setPlainText(i18n.tr("details_none"))
        self.scan_started = time.monotonic()
        self.engine = scanner.ScanEngine(networks, deep=bool(config.get("deep_scan", True)),
                                         host_timeout_ms=int(config.get("scan_timeout_ms", 1500)),
                                         parent=self)
        self.engine.device_found.connect(self._on_device)
        self.engine.progress.connect(self._on_progress)
        self.engine.finished_scan.connect(self._on_scan_done)
        self.engine.start()

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.status_label.setText(i18n.tr("scanning"))
        self.setWindowTitle(f"{i18n.tr('scanning')} — {APP_NAME}")

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
            self.status_label.setText(i18n.tr("scan_stopped"))

    def _on_device(self, device):
        self.model.add_device(device)

    def _on_progress(self, key, done, total):
        if key in ("phase_ping", "phase_ports") and total:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.status_label.setText(i18n.tr(key, done=done, total=total))
        elif key == "phase_finish":
            self.progress.setRange(0, 0)
            self.status_label.setText(i18n.tr("phase_finish"))
        elif key == "phase_done":
            self.status_label.setText(i18n.tr("phase_done", sec=done))
        elif key == "scan_stopped":
            self.status_label.setText(i18n.tr("scan_stopped"))

    def _on_scan_done(self, devices):
        self.engine = None
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setVisible(False)
        self.setWindowTitle(i18n.tr("app_title"))

        devices = devices or []
        self._last_scan_devices = devices
        self._mark_new_devices(devices)
        self.model.set_devices(devices)
        network = self.net_combo.currentData() or ""
        try:
            storage.save_scan(network, devices)
            self._refresh_history()
        except Exception:  # noqa: BLE001
            pass
        self._update_counts(devices)

    def _mark_new_devices(self, devices):
        # Пустышки «только ping» не помечаются новыми — см. fingerprint.mark_new
        fingerprint.mark_new(devices, *storage.seen_macs_and_ips())

    def _update_counts(self, devices=None):
        devices = self.model.devices if devices is None else devices
        total = len(devices)
        android = sum(1 for d in devices if d.verdict == "android")
        new = sum(1 for d in devices if d.is_new)
        self.counts_label.setText(i18n.tr("devices_found", total=total,
                                          android=android, new=new))

    # ------------------------------------------------------------- детали
    def _on_selection(self):
        row = self.table.selectionModel().currentIndex().row()
        device = self.model.device_at(row)
        if device:
            self.details.setPlainText(self._details_text(device))

    @staticmethod
    def _ttl_text(device: Device) -> str:
        if not device.ttl:
            return "—"
        guess = netprobe.ttl_guess(device.ttl)
        if guess:
            return f"{device.ttl} ({i18n.tr('ttl_' + guess)})"
        return str(device.ttl)

    @staticmethod
    def _details_text(device: Device) -> str:
        rows = [
            (i18n.tr("det_ip"), device.ip),
            (i18n.tr("det_mac"), device.mac or "—"),
            (i18n.tr("det_ttl"), MainWindow._ttl_text(device)),
            (i18n.tr("det_vendor"), device.vendor or "—"),
            (i18n.tr("det_hostname"), device.hostname or "—"),
            (i18n.tr("det_type"), type_label(device.device_type)),
            (i18n.tr("det_model"), device.model or "—"),
            (i18n.tr("det_manufacturer"), device.manufacturer or "—"),
            (i18n.tr("det_android"), f"{verdict_label(device.verdict)} ({device.confidence}%)"),
            (i18n.tr("det_ports"), ", ".join(str(p) for p in sorted(device.ports)) or "—"),
            (i18n.tr("det_services"), ", ".join(sorted(device.services)) or "—"),
            (i18n.tr("det_banner"), device.http_banner or "—"),
            (i18n.tr("det_ssdp"), device.ssdp_info or "—"),
            (i18n.tr("det_seen"), datetime.datetime.fromtimestamp(device.seen_ts)
                .strftime("%Y-%m-%d %H:%M:%S")),
        ]
        if device.extras:
            adb = "; ".join(f"{k}={v}" for k, v in sorted(device.extras.items()))
            rows.append((i18n.tr("adb_result"), adb))
        if device.extras.get("adb_android_version"):
            risk = adb_actions.assess_risk(device.extras)
            level_text = i18n.tr("risk_level_" + risk["level"])
            rows.append((i18n.tr("det_risk"),
                         f"{level_text} ({risk['score']})"))
        lines = [f"{name}:  {value}" for name, value in rows]
        if device.evidence:
            lines.append("")
            lines.append(i18n.tr("det_evidence") + ":")
            lines.extend(f"  - {ev}" for ev in device.evidence)
        return "\n".join(lines)

    def query_adb(self):
        row = self.table.selectionModel().currentIndex().row()
        device = self.model.device_at(row)
        if not device:
            return
        # Опрос в фоне: без блокировки интерфейса (ключи/сеть/adb)
        self.adb_btn.setEnabled(False)
        self._adb_device = device
        self.status_label.setText(i18n.tr("adb_running", ip=device.ip))
        self.adb_worker = AdbQueryWorker(device.ip, self)
        self.adb_worker.result.connect(self._on_adb_result)
        self.adb_worker.start()

    def _on_adb_result(self, props, error):
        self.adb_btn.setEnabled(True)
        device = getattr(self, "_adb_device", None)
        if not device:
            return
        source = (props or {}).pop("adb_source", "")
        if props:
            for key, value in props.items():
                device.extras["adb_" + key] = value
            if props.get("model"):
                device.model = device.model or props["model"]
            if props.get("manufacturer"):
                device.manufacturer = device.manufacturer or props["manufacturer"]
            via = "built-in" if source == "native" else "adb"
            device.evidence.append(f"ADB getprop ({via}): Android "
                                   + props.get("android_version", "?"))
            from .. import fingerprint
            fingerprint.classify(device)
            self.model.add_device(device)
            self.details.setPlainText(self._details_text(device))
            self.status_label.setText(i18n.tr("adb_ok"))
            return
        # Ошибки: нет ни встроенного успеха, ни внешнего adb — предлагаем установку
        if error == "adb_missing" or (error.startswith("conn:")
                                      and not adb_info.adb_available()):
            dialog = AdbInstallDialog(self)
            dialog.exec()
            if dialog.adb_path:
                self._retry_adb(device)   # повторный опрос с новым adb
            elif error == "adb_missing" and not adb_info.native_enabled():
                QMessageBox.information(self, i18n.tr("adb_result"),
                                        i18n.tr("adb_not_found"))
            return
        self.status_label.setText(i18n.tr("ready"))
        if error == "unauthorized":
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("adb_unauthorized"))
        else:
            detail = error.split(":", 1)[1] if error.startswith("conn:") else error
            QMessageBox.warning(self, i18n.tr("adb_result"),
                                i18n.tr("adb_conn", ip=device.ip, port=5555,
                                        error=detail[:200]))

    def _retry_adb(self, device):
        """Повторный опрос после установки Platform-Tools."""
        self.adb_btn.setEnabled(False)
        self._adb_device = device
        self.status_label.setText(i18n.tr("adb_running", ip=device.ip))
        self.adb_worker = AdbQueryWorker(device.ip, self)
        self.adb_worker.result.connect(self._on_adb_result)
        self.adb_worker.start()

    def open_toolkit(self):
        row = self.table.selectionModel().currentIndex().row()
        device = self.model.device_at(row)
        if not device:
            return
        AdbToolkitDialog(device, self).exec()

    def open_deep_scan(self):
        row = self.table.selectionModel().currentIndex().row()
        device = self.model.device_at(row)
        if not device:
            return
        self.deepscan_btn.setEnabled(False)

        def _finished():
            self.deepscan_btn.setEnabled(True)
            self.model.add_device(device)
            self.details.setPlainText(self._details_text(device))
            self.status_label.setText(i18n.tr("ready"))

        dialog = DeepScanDialog(device, self)
        # close() только прячет окно; с WA_DeleteOnClose закрытие удалит объект
        # и сработает destroyed -> обновим карточку и вердикт устройства
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        dialog.destroyed.connect(_finished)
        dialog.show()

    def wake_device(self):
        row = self.table.selectionModel().currentIndex().row()
        device = self.model.device_at(row)
        if not device:
            return
        if not device.mac:
            QMessageBox.information(self, i18n.tr("wol_btn"), i18n.tr("wol_no_mac"))
            return
        try:
            netprobe.wake_on_lan(device.mac)
            self.status_label.setText(i18n.tr("wol_sent", mac=device.mac))
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, i18n.tr("wol_btn"),
                                i18n.tr("wol_fail", error=str(exc)[:150]))

    def copy_details(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.details.toPlainText())
        self.status_label.setText(i18n.tr("copied"))

    # ------------------------------------------------------------- экспорт
    def _export(self, kind: str):
        if not self.model.devices:
            return
        default = os.path.join(os.path.expanduser("~"),
                               f"droidscout_report.{kind}")
        if kind == "csv":
            path, _ = QFileDialog.getSaveFileName(self, i18n.tr("export_csv"), default,
                                                  "CSV (*.csv)")
            writer = exporter.export_csv
        else:
            path, _ = QFileDialog.getSaveFileName(self, i18n.tr("export_json"), default,
                                                  "JSON (*.json)")
            writer = exporter.export_json
        if not path:
            return
        try:
            writer(path, self.model.devices)
            self.status_label.setText(i18n.tr("export_done", path=path))
        except OSError as exc:
            QMessageBox.critical(self, i18n.tr("err_title"),
                                 i18n.tr("export_error", error=exc))

    # ------------------------------------------------------------- история
    def _refresh_history(self):
        self.history_list.clear()
        scans = storage.list_scans()
        if not scans:
            item = QListWidgetItem(i18n.tr("history_empty"))
            item.setFlags(Qt.NoItemFlags)
            self.history_list.addItem(item)
            return
        for scan in scans:
            ts = datetime.datetime.fromtimestamp(scan["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            QListWidgetItem(f"{ts}   |   {scan['network']}   |   {scan['total']} / "
                            f"{scan['android']} A", self.history_list, scan["id"])

    def _on_history_pick(self):
        items = self.history_list.selectedItems()
        if not items:
            return
        scan_id = items[0].type()
        rows = storage.scan_devices(scan_id)
        devices = [Device(
            ip=row["ip"] or "", mac=row["mac"] or "", hostname=row["hostname"] or "",
            vendor=row["vendor"] or "", model=row["model"] or "",
            manufacturer=row["manufacturer"] or "", device_type=row["device_type"] or "unknown",
            confidence=row["confidence"] or 0,
            verdict="android" if row["is_android"] else "unknown",
            ports={int(p) for p in (row["ports"] or "").split(",") if p.strip().isdigit()},
            services={s for s in (row["services"] or "").split(",") if s}) for row in rows]
        self.history_model.set_devices(devices)

    def _clear_history(self):
        answer = QMessageBox.question(self, i18n.tr("confirm_title"),
                                      i18n.tr("history_confirm"),
                                      QMessageBox.Yes | QMessageBox.No)
        if answer == QMessageBox.Yes:
            storage.clear()
            self.history_model.set_devices([])
            self._refresh_history()

    # ------------------------------------------------------------- тема/язык
    def toggle_theme(self):
        new_theme = "light" if config.get("theme", "dark") == "dark" else "dark"
        config.set_key("theme", new_theme)
        apply_theme(QApplication.instance(), new_theme)
        self._paint_bg(self.tabs)
        self._paint_bg(self.tabs.tabBar())

    def toggle_language(self):
        current = i18n.detect_language()
        new_lang = "en" if current == "ru" else "ru"
        config.set_key("language", new_lang)
        self.retranslate()

    def retranslate(self):
        i18n.set_language(i18n.detect_language())
        self.setWindowTitle(i18n.tr("app_title"))
        self.scan_btn.setText(i18n.tr("scan"))
        self.stop_btn.setText(i18n.tr("scan_stop"))
        self.net_label.setText(i18n.tr("network"))
        self.export_btn.setText(i18n.tr("export"))
        self.csv_action.setText(i18n.tr("export_csv"))
        self.json_action.setText(i18n.tr("export_json"))
        self.theme_btn.setText(i18n.tr("theme_dark") + " / " + i18n.tr("theme_light"))
        self.update_btn.setText(i18n.tr("check_updates"))
        self.settings_btn.setText(i18n.tr("settings"))
        self.tabs.setTabText(0, i18n.tr("tab_scan"))
        self.tabs.setTabText(1, i18n.tr("tab_history"))
        self.details_title.setText(i18n.tr("device_details"))
        self.adb_btn.setText(i18n.tr("adb_details"))
        self.toolkit_btn.setText(i18n.tr("adb_toolkit_btn"))
        self.copy_btn.setText(i18n.tr("copy_info"))
        self.clear_history_btn.setText(i18n.tr("history_delete"))
        self.model.refresh_headers()
        self.history_model.refresh_headers()
        self._update_counts()

    # ------------------------------------------------------------- обновления
    def check_updates_silent(self):
        self.update_worker = UpdateWorker(self)
        self.update_worker.checked.connect(self._on_update_checked)
        self.update_worker.failed.connect(lambda _e: None)  # тихо
        self.update_worker.start()

    def check_updates_manual(self):
        self.status_label.setText(i18n.tr("update_checking"))
        self.update_btn.setEnabled(False)
        self.update_worker = UpdateWorker(self)
        self.update_worker.checked.connect(self._on_update_checked)
        self.update_worker.failed.connect(self._on_update_failed)
        self.update_worker.start()

    def _on_update_checked(self, release):
        self.update_btn.setEnabled(True)
        self.status_label.setText(i18n.tr("ready"))
        if release:
            UpdateDialog(release, self).exec()
        else:
            QMessageBox.information(self, i18n.tr("check_updates"),
                                    i18n.tr("update_latest", version=__version__))

    def _on_update_failed(self, error):
        self.update_btn.setEnabled(True)
        self.status_label.setText(i18n.tr("ready"))
        message = i18n.tr("update_fail", error=error[:200])
        if "401" in error or "404" in error:
            message += "\n\n" + i18n.tr("update_private_hint")
        QMessageBox.warning(self, i18n.tr("err_title"), message)

    # ------------------------------------------------------------- настройки
    def open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec():
            data = getattr(dialog, "result_data", {})
            if data.get("ui_changed"):
                apply_theme(QApplication.instance())
                self._paint_bg(self.tabs)
                self._paint_bg(self.tabs.tabBar())
                self.retranslate()
