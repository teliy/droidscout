"""ADB-инструментарий: диалог с вкладками поверх adb_actions.

Вкладки: Инфо (батарея/память/диск/экран/риск), Железо (полный опрос),
Монитор (живые CPU/RAM/батарея/температуры), Настройки, Действия
(тумблеры Wi-Fi/данные/Bluetooth/полёт, экран, яркость), Приложения
(запуск, остановка, удаление, отключение, очистка, установка APK),
Пульт (D-pad, звук, питание, ввод текста), Скриншот, Файлы,
Консоль (shell) и Логкат.

Каждая операция выполняется в фоновом потоке (ActionWorker) — интерфейс
не блокируется. Ошибки ActionError переводятся на язык интерфейса.
"""

import datetime
import hashlib
import os
import re
import threading

from PySide6.QtCore import QObject, QRect, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QImage, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog,
                               QFileDialog, QFormLayout, QFrame, QGridLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QMenu, QMessageBox, QPlainTextEdit,
                               QProgressDialog, QPushButton, QScrollArea,
                               QSpinBox, QStyle, QStyledItemDelegate,
                               QStyleOptionViewItem, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import adb_actions, exporter, favorites, hw_info, i18n, journal
from .journal_dialog import JournalDialog
from .sort_items import NaturalTreeItem
from .theme import is_dark_theme

RISK_COLORS = {"low": "#43a047", "medium": "#fb8c00",
               "high": "#f4511e", "critical": "#e53935"}

APPS_COLUMNS = ("pkg", "version", "path")

# Ошибки транспорта на уровне протокола: обычно это кривая/зависшая прошивка,
# а не выключенный ADB — нужна другая подсказка, чем для "connect: ..."
_PROTO_ERR_RE = re.compile(r"corrupted|closed by device|handshake|unexpected packet", re.I)

VT_URL = "https://www.virustotal.com/gui/search/"


class _HwWrapDelegate(QStyledItemDelegate):
    """Перенос длинных значений по словам в колонке «Значение».

    QTreeWidget по умолчанию обрезает длинный текст (сборка ядра, строки
    GLES, device-tree), а единая высота строк не даёт показать его целиком.
    Делегат рисует текст с переносом и вычисляет высоту строки так, чтобы
    влезал весь текст; колонка «Параметр» остаётся без изменений.
    """

    PAD = 10  # запас по краям ячейки, чтобы текст не прилипал к границе

    def __init__(self, tree, col):
        super().__init__(tree)
        self._tree = tree
        self._col = col

    def _opt(self, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.features |= QStyleOptionViewItem.WrapText
        opt.textElideMode = Qt.ElideNone
        return opt

    def paint(self, painter, option, index):
        opt = self._opt(option, index)
        painter.save()
        painter.setClipRect(option.rect)
        style = opt.widget.style() if opt.widget is not None \
            else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, opt.widget)
        painter.restore()

    def sizeHint(self, option, index):
        if index.column() != self._col:
            return super().sizeHint(option, index)
        opt = self._opt(option, index)
        width = self._tree.columnWidth(self._col) - 2 * self.PAD
        if width < 60:
            width = 60
        rect = opt.fontMetrics.boundingRect(
            QRect(0, 0, width, 100000),
            Qt.TextWordWrap | Qt.TextWrapAnywhere, opt.text)
        base = super().sizeHint(option, index)
        height = max(base.height(), rect.height() + self.PAD)
        return QSize(base.width(), height)


# ------------------------------------------------------------- формат железа
def _hw_freq(khz) -> str:
    """Частота в кГц -> «1512 МГц» / «1.51 ГГц» (единицы из i18n)."""
    if not khz:
        return ""
    mhz = khz / 1000.0
    if mhz >= 1000:
        text = f"{mhz / 1000:.2f}".rstrip("0").rstrip(".")
        return i18n.tr("hw_ghz_fmt", v=text)
    return i18n.tr("hw_mhz_fmt", v=int(mhz))


def _hw_size(mb) -> str:
    """МБ -> «7.4 ГБ» / «512 МБ»."""
    if mb is None or mb <= 0:
        return ""
    if mb >= 1024:
        return i18n.tr("hw_gb_fmt", v=f"{mb / 1024:.1f}")
    return i18n.tr("hw_mb_fmt", v=mb)


def _hw_arch_label(arch: str) -> str:
    """uname -m -> расшифровка (aarch64 — ARMv8-A, 64 бита)."""
    key = {"aarch64": "hw_arch_aarch64", "armv7l": "hw_arch_armv7l",
           "armv8l": "hw_arch_armv8l", "x86_64": "hw_arch_x86_64",
           "x86": "hw_arch_x86", "i686": "hw_arch_x86",
           "i386": "hw_arch_x86"}.get((arch or "").lower())
    return i18n.tr(key) if key else (arch or "")


def _hw_abi_label(abi: str) -> str:
    """ro.product.cpu.abi -> расшифровка разрядности."""
    key = {"arm64-v8a": "hw_abi_arm64_v8a",
           "armeabi-v7a": "hw_abi_armeabi_v7a",
           "x86_64": "hw_abi_x86_64", "x86": "hw_abi_x86"}.get(abi or "")
    return i18n.tr(key) if key else (abi or "")


_TZ_KEYS = (("cpu", "hw_tz_cpu"), ("gpu", "hw_tz_gpu"),
            ("ddr", "hw_tz_ddr"), ("video", "hw_tz_ve"),
            ("soc", "hw_tz_soc"), ("board", "hw_tz_board"),
            ("battery", "hw_tz_battery"), ("charger", "hw_tz_charger"),
            ("wifi", "hw_tz_wifi"), ("modem", "hw_tz_modem"),
            ("npu", "hw_tz_npu"), ("usbc", "hw_tz_usbc"),
            ("skin", "hw_tz_skin"))


def _hw_tz_label(ztype: str) -> str:
    """Тип термозоны (cpu_thermal) -> подпись («Процессор»)."""
    low = (ztype or "").lower()
    for token, key in _TZ_KEYS:
        if token in low:
            return i18n.tr(key)
    return ztype or ""


_IF_KEYS = (("wlan", "hw_if_wlan"), ("eth", "hw_if_eth"),
            ("p2p", "hw_if_p2p"), ("rmnet", "hw_if_rmnet"),
            ("tun", "hw_if_tun"), ("dummy", "hw_if_dummy"),
            ("ap", "hw_if_ap"), ("lo", "hw_if_lo"))


def _hw_if_label(iface: str) -> str:
    """Имя интерфейса (eth0) -> подпись («Ethernet»); иначе ''."""
    low = (iface or "").lower()
    for token, key in _IF_KEYS:
        if token in low:
            return i18n.tr(key)
    return ""


def _local_sha256(path: str) -> str:
    """SHA-256 файла на ПК (для проверки пакета на VirusTotal)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _human_mb(num_bytes: int) -> str:
    """48 019 632 -> «45,8 МБ» (меньше мегабайта — в КБ)."""
    if num_bytes < 1024 * 1024:
        return ("%.0f КБ" % (num_bytes / 1024)).replace(".", ",")
    return ("%.1f МБ" % (num_bytes / 1048576)).replace(".", ",")


def _friendly_error(exc: Exception, ip: str) -> str:
    """ActionError -> понятный локализованный текст."""
    if isinstance(exc, adb_actions.ActionError):
        if exc.code == "unauthorized":
            return i18n.tr("adb_unauthorized")
        if exc.code == "cancel":
            return i18n.tr("err_cancelled")
        if exc.code == "wake":
            return i18n.tr("err_wake")
        if exc.code == "space":
            return i18n.tr("err_space", details=str(exc))
        if exc.code == "timeout":
            return i18n.tr("err_timeout", stage=str(exc))
        if exc.code == "pm":
            return i18n.tr("err_pm", output=str(exc))
        if exc.code == "conn":
            key = "adb_conn_protocol" if _PROTO_ERR_RE.search(str(exc)) else "adb_conn"
            return i18n.tr(key, ip=ip, port=5555, error=str(exc)[:150])
        if exc.code == "denied":
            return i18n.tr("files_denied",
                           path=str(exc).rsplit(": ", 1)[-1])
        if exc.code == "nopath":
            return i18n.tr("files_nopath", path=str(exc).rsplit(": ", 1)[-1])
    return str(exc)[:250]


class ActionWorker(QThread):
    """Выполняет fn() в фоне; результат или исключение — сигналом."""

    result = Signal(object, object)          # значение | None, Exception | None

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            self.result.emit(self._fn(), None)
        except Exception as exc:  # noqa: BLE001 — показываем в UI
            self.result.emit(None, exc)


class ProgressBridge(QObject):
    """Прогресс из Worker-потока в UI: сигнал вместо прямого вызова.

    Колбэк push'а дёргается из QThread — трогать виджеты оттуда нельзя;
    эмитим Signal(int, int), Qt сам маршалит вызов в GUI-поток.
    """

    tick = Signal(int, int)


class AdbToolkitDialog(QDialog):
    """Инструментарий ADB для одного устройства."""

    def __init__(self, device, parent=None):
        super().__init__(parent)
        self.device = device
        self.ip = device.ip
        self._workers = []
        self._shell_history = []
        self._shell_index = -1
        self._shot_png = b""
        self._root_info = {}
        self._dev_loaded = False
        self._pdns_loaded = False
        self._act_loaded = False
        self._mon_busy = False
        self._mon_fails = 0
        self._prev_cpu = None
        self.fav_apps = set(favorites.load(favorites.APPS_KEY))

        self.setWindowTitle(i18n.tr("toolkit_title", ip=self.ip))
        self.resize(760, 600)

        root = QVBoxLayout(self)
        header = QLabel(f"<b>{self.device.model or self.device.hostname or 'Android'}</b>"
                        f" — {self.ip}:5555")
        root.addWidget(header)

        self.risk_label = QLabel(i18n.tr("toolkit_checking"))
        self.risk_label.setWordWrap(True)
        root.addWidget(self.risk_label)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_info(), i18n.tr("tab_adb_info"))
        self.tabs.addTab(self._tab_hw(), i18n.tr("tab_adb_hw"))
        self._monitor_page = self._tab_monitor()
        self.tabs.addTab(self._monitor_page, i18n.tr("tab_adb_monitor"))
        self._settings_page = self._tab_settings()
        self.tabs.addTab(self._settings_page, i18n.tr("tab_adb_settings"))
        self.tabs.currentChanged.connect(self._maybe_load_settings)
        self._actions_page = self._tab_actions()
        self.tabs.addTab(self._actions_page, i18n.tr("tab_adb_actions"))
        self.tabs.currentChanged.connect(self._maybe_actions)
        self.tabs.addTab(self._tab_apps(), i18n.tr("tab_adb_apps"))
        self.tabs.addTab(self._tab_remote(), i18n.tr("tab_adb_remote"))
        self.tabs.addTab(self._tab_screenshot(), i18n.tr("tab_adb_shot"))
        self.tabs.addTab(self._tab_files(), i18n.tr("tab_adb_files"))
        self.tabs.addTab(self._tab_shell(), i18n.tr("tab_adb_shell"))
        self.tabs.addTab(self._tab_logcat(), i18n.tr("tab_adb_logcat"))
        root.addWidget(self.tabs, 1)

        bottom = QHBoxLayout()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        bottom.addWidget(self.status, 1)
        journal_btn = QPushButton(i18n.tr("journal_btn"))
        journal_btn.clicked.connect(self._open_journal)
        bottom.addWidget(journal_btn)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        bottom.addWidget(close_btn)
        root.addLayout(bottom)

        # при открытии: live-проверка root/secure + статистика + железо
        self._run(self._on_root_info, adb_actions.check_root, self.ip)
        self.refresh_stats()
        self.refresh_hw()

    # ------------------------------------------------------------ инфраструктура
    def _run(self, callback, fn, *args, **kwargs):
        # Отметка действия пользователя в журнале: видно, какую кнопку нажали
        journal.action(getattr(fn, "__name__", "action") or "action", args)
        worker = ActionWorker(lambda: fn(*args, **kwargs), self)
        worker.result.connect(callback)
        self._workers.append(worker)
        worker.start()
        return worker

    def _run_with_progress(self, title_key, transfer_key, callback, fn,
                           *args, finish_busy=False, **kwargs):
        """Запускает fn в фоне с диалогом прогресса передачи.

        progress(s, t): s<t — процент передачи; s==t — передача окончена:
        при finish_busy диалог переключается в «занят» (идёт pm install),
        иначе закрывается. Кнопка «Отмена» останавливает передачу между
        чанками (should_stop), ошибка/отмена покажутся как обычно.
        """
        bridge = ProgressBridge()
        self._progress_bridge = bridge       # держим ссылку до конца работы
        self._cancel_event = threading.Event()
        dlg = QProgressDialog("", i18n.tr("cancel_btn"), 0, 100, self)
        dlg.setWindowTitle(i18n.tr(title_key))
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.setMinimumWidth(380)
        dlg.setAutoClose(False)
        dlg.setAutoReset(False)
        dlg.canceled.connect(self._cancel_event.set)
        self._progress_dlg = dlg
        self._progress_state = {"transfer_key": transfer_key,
                                "finish_busy": finish_busy}
        bridge.tick.connect(self._on_transfer_tick)
        dlg.show()
        kwargs.setdefault("progress", lambda s, t: bridge.tick.emit(s, t))
        kwargs.setdefault("should_stop", self._cancel_event.is_set)
        self._run(callback, fn, *args, **kwargs)

    def _on_transfer_tick(self, sent, total):
        dlg = self._progress_dlg
        if dlg is None:
            return
        state = self._progress_state or {}
        if sent >= total:
            if state.get("finish_busy"):
                dlg.setRange(0, 0)           # «занят»: идёт pm install
                dlg.setLabelText(i18n.tr("progress_installing"))
            else:
                dlg.close()
            return
        dlg.setLabelText(i18n.tr(state.get("transfer_key", ""),
                                 sent=_human_mb(sent),
                                 total=_human_mb(total)))
        dlg.setValue(int(sent * 100 / max(total, 1)))

    def _close_progress(self):
        dlg = getattr(self, "_progress_dlg", None)
        if dlg is not None:
            dlg.close()
            self._progress_dlg = None
        self._progress_state = None

    def _open_journal(self):
        JournalDialog(self).show()

    def _busy(self, text_key="toolkit_busy"):
        self.status.setText(i18n.tr(text_key))

    def _idle(self):
        self.status.setText("")

    def _failed(self, exc):
        self.status.setText(i18n.tr("toolkit_error", error=_friendly_error(exc, self.ip)))

    # ---------------------------------------------------------------- таб: Инфо
    def _tab_info(self):
        page = QWidget()
        form = QFormLayout(page)
        self.stat_labels = {}
        for key in ("stat_battery", "stat_memory", "stat_disk", "stat_display",
                    "stat_thermal", "stat_load", "stat_uptime",
                    "stat_device_ip", "stat_root"):
            label = QLabel("—")
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.stat_labels[key] = label
            form.addRow(i18n.tr(key), label)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton(i18n.tr("stat_refresh"))
        refresh_btn.clicked.connect(self.refresh_stats)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch(1)
        form.addRow(btn_row)

        # Перезагрузка — выше блока «Экран»: видна сразу, без прокрутки.
        reboot_box = QGroupBox(i18n.tr("reboot_group"))
        reboot_row = QHBoxLayout(reboot_box)
        for mode, key in (("", "reboot_normal"), ("recovery", "reboot_recovery"),
                          ("bootloader", "reboot_bootloader")):
            btn = QPushButton(i18n.tr(key))
            btn.clicked.connect(lambda _=False, m=mode: self._reboot(m))
            reboot_row.addWidget(btn)
        form.addRow(reboot_box)

        screen_box = QGroupBox(i18n.tr("screen_group"))
        screen_grid = QGridLayout(screen_box)
        self._wm_fn = {"size": adb_actions.wm_size_set,
                       "density": adb_actions.wm_density_set,
                       "overscan": adb_actions.wm_overscan_set}
        self._wm_buttons = {}
        for row, (kind, label_key, placeholder) in enumerate((
                ("size", "screen_size", "1920x1080"),
                ("density", "screen_density", "160"),
                ("overscan", "screen_overscan", "-40,-40,-40,-40"))):
            screen_grid.addWidget(QLabel(i18n.tr(label_key)), row, 0)
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            setattr(self, f"screen_{kind}_input", edit)
            screen_grid.addWidget(edit, row, 1)
            apply_btn = QPushButton(i18n.tr("screen_apply"))
            apply_btn.clicked.connect(lambda _=False, k=kind: self._wm_apply(k))
            screen_grid.addWidget(apply_btn, row, 2)
            reset_btn = QPushButton(i18n.tr("screen_reset"))
            reset_btn.clicked.connect(lambda _=False, k=kind: self._wm_reset(k))
            screen_grid.addWidget(reset_btn, row, 3)
            self._wm_buttons[kind] = (apply_btn, reset_btn)
        screen_hint = QLabel(i18n.tr("screen_hint"))
        screen_hint.setWordWrap(True)
        screen_grid.addWidget(screen_hint, 3, 0, 1, 4)
        form.addRow(screen_box)

        # Прокрутка: с блоками «Экран» и «Перезагрузка» вкладка может не
        # влезать по высоте — всё содержимое доступно скроллом.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        outer = QWidget()
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.addWidget(scroll)
        return outer

    # ------------------------------------------------------------ таб: Железо
    def _tab_hw(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        sum_box = QGroupBox(i18n.tr("hw_summary_box"))
        sum_lay = QVBoxLayout(sum_box)
        self.hw_summary = QLabel("—")
        self.hw_summary.setWordWrap(True)
        self.hw_summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        sum_lay.addWidget(self.hw_summary)
        layout.addWidget(sum_box)

        self.hw_tree = QTreeWidget()
        self.hw_tree.setColumnCount(2)
        self.hw_tree.setHeaderLabels([i18n.tr("hw_col_param"),
                                      i18n.tr("hw_col_value")])
        self.hw_tree.setColumnWidth(0, 250)
        # Длинные значения (сборка ядра, GLES, device-tree) переносим по словам,
        # а не обрезаем: высота строки подгоняется под весь текст.
        self.hw_tree.setItemDelegateForColumn(
            1, _HwWrapDelegate(self.hw_tree, 1))
        # При смене ширины колонки высоты строк пересчитываются под новый перенос.
        self.hw_tree.header().sectionResized.connect(self._hw_relayout)
        layout.addWidget(self.hw_tree, 1)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton(i18n.tr("stat_refresh"))
        refresh_btn.clicked.connect(self.refresh_hw)
        btn_row.addWidget(refresh_btn)
        copy_btn = QPushButton(i18n.tr("hw_copy"))
        copy_btn.clicked.connect(self._hw_copy)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)
        return page

    def refresh_hw(self):
        self._busy("hw_busy")
        self._run(self._on_hw, hw_info.read_hw, self.ip)

    def _hw_relayout(self, *args):
        """Пересчитать высоты строк после изменения ширины колонки."""
        self.hw_tree.doItemsLayout()

    def _on_hw(self, hw, exc):
        if exc:
            self._failed(exc)
            self.hw_summary.setText("—")
            return
        self._idle()
        self._hw_fill(hw or {})

    def _hw_copy(self):
        lines = []
        for i in range(self.hw_tree.topLevelItemCount()):
            head = self.hw_tree.topLevelItem(i)
            lines.append(head.text(0))
            for j in range(head.childCount()):
                child = head.child(j)
                param, value = child.text(0), child.text(1)
                lines.append(f"  {param}: {value}" if param
                             else f"  {value}")
        QApplication.clipboard().setText("\n".join(lines))
        self.status.setText(i18n.tr("copied"))

    # -- сборка секций вкладки «Железо» -------------------------------------
    @staticmethod
    def _hw_section(tree, title, rows):
        """Секция-родитель с жирным заголовком. Строка показывается, если
        задан хотя бы один из столбцов — так секции с частичными данными
        не теряют подписи."""
        head = QTreeWidgetItem([title, ""])
        font = head.font(0)
        font.setBold(True)
        head.setFont(0, font)
        tree.addTopLevelItem(head)
        for param, value in rows:
            if not param and not value:
                continue
            child = QTreeWidgetItem([param or "", value or ""])
            # Полный текст доступен и во всплывающей подсказке.
            if len(value or "") > 60:
                child.setToolTip(1, value)
            if len(param or "") > 60:
                child.setToolTip(0, param)
            head.addChild(child)
        head.setExpanded(True)

    @staticmethod
    def _hw_gov_text(governor: str) -> str:
        desc_key = f"hw_gov_{governor}"
        desc = i18n.tr(desc_key)
        return f"{governor} — {desc}" if desc != desc_key else governor

    @staticmethod
    def _hw_cores_text(cpuinfo: dict) -> str:
        parts = []
        for impl, part, count in cpuinfo.get("cores_detail") or []:
            decoded = hw_info.decode_arm_core(impl, part)
            name = decoded[1] if decoded else i18n.tr(
                "hw_unknown_core", impl=impl, part=part)
            parts.append(i18n.tr("hw_cores_fmt", n=count, name=name))
        if parts:
            return ", ".join(parts)
        if cpuinfo.get("model_name"):
            return cpuinfo["model_name"]
        if cpuinfo.get("cores"):
            return i18n.tr("hw_cores_fmt", n=cpuinfo["cores"],
                           name=i18n.tr("hw_unknown"))
        return ""

    @staticmethod
    def _hw_freq_text(cpufreq: list) -> str:
        mins = [e["min_khz"] for e in cpufreq if e.get("min_khz")]
        maxs = [e["max_khz"] for e in cpufreq if e.get("max_khz")]
        curs = [e["cur_khz"] for e in cpufreq if e.get("cur_khz")]
        if not maxs:
            return ""
        text = f"{_hw_freq(min(mins))} – {_hw_freq(max(maxs))}" \
            if mins else _hw_freq(max(maxs))
        if curs:
            text += f" ({i18n.tr('hw_cur_fmt', v=_hw_freq(max(curs)))})"
        return text

    @staticmethod
    def _hw_gpu_text(gpu: dict) -> str:
        renderer = gpu.get("renderer", "")
        family = gpu.get("family", "")
        if not renderer:
            return ""
        if family == "software-render":
            return i18n.tr("hw_gpu_software")
        if family and " (" in family:
            arch = family.split(" (", 1)[1].rstrip(")")
            return f"{renderer} — {arch}"
        if family:
            return f"{renderer} — {family}"
        return renderer

    def _hw_fill(self, hw: dict):
        props = hw.get("props") or {}
        cpuinfo = hw.get("cpuinfo") or {}
        cpufreq = hw.get("cpufreq") or []
        gpu = hw.get("gpu") or {}
        mem = hw.get("memory") or {}
        kernel = hw.get("kernel") or {}
        soc_list = hw.get("soc") or []

        soc_txt = ""
        if soc_list:
            first = soc_list[0]
            soc_txt = f"{first['vendor']} {first['model']}".strip()
        cores_txt = self._hw_cores_text(cpuinfo)
        freq_txt = self._hw_freq_text(cpufreq)
        gpu_txt = self._hw_gpu_text(gpu)
        ram_txt = _hw_size(mem.get("total_mb"))
        blocks = hw.get("block") or []
        storage_txt = ""
        if blocks and blocks[0].get("size_gb"):
            storage_txt = _hw_size(int(round(blocks[0]["size_gb"] * 1024)))

        self.hw_summary.setText(i18n.tr(
            "hw_summary_fmt",
            soc=soc_txt or i18n.tr("hw_unknown"),
            cores=cores_txt or "—", freq=freq_txt or "—",
            gpu=gpu_txt or "—", ram=ram_txt or "—",
            storage=storage_txt or "—"))

        tree = self.hw_tree
        tree.clear()

        # --- Процессор (SoC и ядра) -----------------------------------------
        rows = [(i18n.tr("hw_soc"),
                 soc_txt or i18n.tr("hw_soc_undetected")),
                (i18n.tr("hw_cores"), cores_txt),
                (i18n.tr("hw_freq"), freq_txt)]
        groups = {}
        for entry in cpufreq:
            key = (entry.get("min_khz"), entry.get("max_khz"),
                   entry.get("governor"))
            groups.setdefault(key, []).append(entry["core"])
        for (mn, mx, gov), cores in groups.items():
            lo, hi = min(cores), max(cores)
            label = f"cpu{lo}" if lo == hi else f"cpu{lo}–cpu{hi}"
            value = f"{_hw_freq(mn)} – {_hw_freq(mx)}" if mn \
                else _hw_freq(mx)
            if gov:
                value += f" · {self._hw_gov_text(gov)}"
            rows.append((label, value))
        govs = hw.get("governors_available") or []
        if not groups and cpufreq and cpufreq[0].get("governor"):
            rows.append((i18n.tr("hw_governor"),
                         self._hw_gov_text(cpufreq[0]["governor"])))
        if govs:
            rows.append((i18n.tr("hw_govs_avail"), ", ".join(govs)))
        feats = cpuinfo.get("features") or []
        tokens = set(feats)
        rows += [
            (i18n.tr("hw_arch"), _hw_arch_label(kernel.get("arch"))),
            (i18n.tr("hw_arch_abi"),
             _hw_abi_label(props.get("ro.product.cpu.abi", ""))),
            (i18n.tr("hw_model_name"), cpuinfo.get("model_name", "")),
            (i18n.tr("hw_hw"), cpuinfo.get("hardware", "")),
        ]
        if feats:
            shown = " ".join(feats[:14])
            if len(feats) > 14:
                shown += " …"
            rows.append((i18n.tr("hw_cpu_feat"), shown))
        rows += [
            (i18n.tr("hw_neon"),
             i18n.tr("hw_yes") if {"asimd", "neon"} & tokens
             else i18n.tr("hw_no")),
            (i18n.tr("hw_aes"),
             i18n.tr("hw_yes") if "aes" in tokens else i18n.tr("hw_no")),
            (i18n.tr("hw_sha"),
             i18n.tr("hw_yes") if {"sha1", "sha2"} & tokens
             else i18n.tr("hw_no")),
        ]
        if cpuinfo.get("bogo") is not None:
            rows.append((i18n.tr("hw_bogo"), f"{cpuinfo['bogo']:.2f}"))
        self._hw_section(tree, i18n.tr("hw_sec_cpu"), rows)

        # --- Графика (GPU) ----------------------------------------------------
        gpu_rows = [
            (i18n.tr("hw_gpu"), gpu_txt),
            (i18n.tr("hw_gles_vendor"), gpu.get("vendor", "")),
            (i18n.tr("hw_gles_version"), gpu.get("version", "")),
            (i18n.tr("hw_egl"), props.get("ro.hardware.egl", "")),
        ]
        if not gpu:
            gpu_rows.append(("", i18n.tr("hw_gpu_undetected")))
        self._hw_section(tree, i18n.tr("hw_sec_gpu"), gpu_rows)

        # --- Оперативная память --------------------------------------------------
        used_pct = mem.get("used_pct")
        swap = ""
        if mem.get("swap_total_mb"):
            free_txt = _hw_size(mem.get("swap_free_mb"))
            swap = f"{_hw_size(mem['swap_total_mb'])} " \
                   f"({i18n.tr('hw_swap_free_fmt', v=free_txt)})"
        ram_rows = [
            (i18n.tr("hw_ram_total"), _hw_size(mem.get("total_mb"))),
            (i18n.tr("hw_ram_avail"), _hw_size(mem.get("available_mb"))),
            (i18n.tr("hw_ram_cached"), _hw_size(mem.get("cached_mb"))),
            (i18n.tr("hw_ram_used"),
             i18n.tr("hw_pct_fmt", v=used_pct)
             if used_pct is not None else ""),
            (i18n.tr("hw_ram_swap"), swap),
            ("", i18n.tr("hw_ram_note") if mem.get("total_mb") else ""),
        ]
        self._hw_section(tree, i18n.tr("hw_sec_ram"), ram_rows)

        # --- Накопители ------------------------------------------------------------
        partitions = hw.get("partitions") or []
        st_rows = []
        for blk in blocks:
            chip = f" — {blk['chip']}" if blk.get("chip") else ""
            st_rows.append((i18n.tr("hw_disk_chip"), f"{blk['name']}{chip}"))
            if blk.get("size_gb"):
                st_rows.append((i18n.tr("hw_disk_size"),
                                _hw_size(int(round(blk["size_gb"] * 1024)))))
        if partitions:
            st_rows.append((i18n.tr("hw_parts_count"),
                            str(len(partitions))))
            top = [f"{p['name']} {_hw_size(p['mb'])}"
                   for p in sorted(partitions, key=lambda x: -x["mb"])[:4]]
            st_rows.append((i18n.tr("hw_parts_top"), " · ".join(top)))
        for item in (hw.get("storage") or [])[:8]:
            st_rows.append((item["mount"],
                            f"{_hw_size(item['total_mb'])}, "
                            f"{i18n.tr('hw_pct_fmt', v=item['used_pct'])}"))
        self._hw_section(tree, i18n.tr("hw_sec_storage"), st_rows)

        # --- Дисплей -----------------------------------------------------------------
        disp = hw.get("display") or {}
        size = disp.get("size", "")
        if disp.get("override_size"):
            size = f"{size} → {disp['override_size']}"
        density = disp.get("density", "")
        if disp.get("override_density"):
            density = f"{density} → {disp['override_density']}"
        fps = disp.get("fps")
        self._hw_section(tree, i18n.tr("hw_sec_display"), [
            (i18n.tr("hw_disp_res"), size),
            (i18n.tr("hw_disp_dens"),
             f"{density} dpi" if density else ""),
            (i18n.tr("hw_disp_fps"),
             i18n.tr("hw_fps_fmt", v=fps) if fps else ""),
        ])

        # --- Батарея --------------------------------------------------------------------
        batt = hw.get("battery") or {}
        batt_rows = []
        if batt.get("level") is not None:
            batt_rows.append((i18n.tr("hw_batt_level"),
                              i18n.tr("hw_pct_fmt", v=batt["level"])))
        for key, label in (("status", "hw_batt_status"),
                           ("health", "hw_batt_health")):
            value = batt.get(key)
            if value:
                batt_rows.append((i18n.tr(label),
                                  i18n.tr(f"{label}_{value}")))
        if batt.get("technology"):
            batt_rows.append((i18n.tr("hw_batt_tech"), batt["technology"]))
        if batt.get("voltage_mv"):
            batt_rows.append((i18n.tr("hw_batt_voltage"),
                              i18n.tr("hw_mv_fmt", v=batt["voltage_mv"])))
        if batt.get("temp_c") is not None:
            batt_rows.append((i18n.tr("hw_batt_temp"),
                              i18n.tr("hw_temp_fmt", v=batt["temp_c"])))
        if not batt_rows:
            batt_rows.append(("", i18n.tr("hw_batt_absent")))
        self._hw_section(tree, i18n.tr("hw_sec_battery"), batt_rows)

        # --- Датчики температуры ------------------------------------------------------------
        tz_rows = []
        for zone in hw.get("thermal") or []:
            label = _hw_tz_label(zone.get("type", ""))
            tz_rows.append((label or zone.get("type", ""),
                            i18n.tr("hw_temp_fmt", v=zone["temp_c"])))
        self._hw_section(tree, i18n.tr("hw_sec_thermal"), tz_rows)

        # --- Датчики ----------------------------------------------------------------------------
        sensors = hw.get("sensors") or []
        if sensors:
            sensor_rows = [(i18n.tr("hw_sensors_count_fmt", n=len(sensors)), "")]
            for item in sensors[:30]:
                sensor_rows.append((item["name"], item.get("vendor", "")))
            self._hw_section(tree, i18n.tr("hw_sec_sensors"), sensor_rows)

        # --- Сеть -------------------------------------------------------------------------------
        net_rows = []
        for iface in hw.get("net") or []:
            label = _hw_if_label(iface["iface"])
            name = f"{iface['iface']} — {label}" if label else iface["iface"]
            value = ", ".join(iface["ips"]) if iface.get("ips") \
                else i18n.tr("hw_no_ip")
            if iface.get("mac"):
                value += f" · {iface['mac']}"
            net_rows.append((name, value))
        self._hw_section(tree, i18n.tr("hw_sec_net"), net_rows)

        # --- Ядро и система -----------------------------------------------------------------------
        days, rest = divmod(int(hw.get("uptime_sec") or 0), 86400)
        hours, minutes = divmod(rest // 60, 60)
        self._hw_section(tree, i18n.tr("hw_sec_kernel"), [
            (i18n.tr("hw_kernel_ver"), kernel.get("version", "")),
            (i18n.tr("hw_kernel_raw"),
             (kernel.get("raw", "") or "")[:300]),
            (i18n.tr("hw_kernel_arch"),
             _hw_arch_label(kernel.get("arch")) or kernel.get("arch", "")),
            (i18n.tr("hw_uptime"), i18n.tr("stat_uptime_fmt", days=days,
                                            hours=hours, minutes=minutes)),
        ])

        # --- Платформа -------------------------------------------------------------------------------
        dt = hw.get("dt") or {}
        plat_rows = [(i18n.tr("hw_dt_model"), dt.get("model", ""))]
        for comp in (dt.get("compatible") or [])[:6]:
            plat_rows.append((i18n.tr("hw_dt_compat"), comp))
        for item in soc_list[:4]:
            plat_rows.append((i18n.tr("hw_soc_sources"), i18n.tr(
                "hw_sources_fmt",
                model=f"{item['vendor']} {item['model']}".strip(),
                source=item["source"])))
        if hw.get("platform"):
            plat_rows.append((i18n.tr("hw_platform_sys"),
                              ", ".join(hw["platform"][:10])))
        self._hw_section(tree, i18n.tr("hw_sec_platform"), plat_rows)

        # --- Аппаратные возможности ---------------------------------------------------------------------
        features = hw.get("features") or []
        if features:
            key_feats = [f for f in features
                         if any(t in f for t in ("wifi", "bluetooth",
                                                 "ethernet", "camera",
                                                 "location", "nfc",
                                                 "microphone", "usb",
                                                 "leanback", "live_tv"))]
            self._hw_section(tree, i18n.tr("hw_sec_features"), [
                (i18n.tr("hw_feat_count_fmt", n=len(features)), ""),
                (i18n.tr("hw_feat_keys"),
                 ", ".join(key_feats) if key_feats else ""),
                ("", "\n".join(features)),
            ])

    # ------------------------------------------------------------ таб: Монитор
    def _tab_monitor(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        self.mon_auto = QCheckBox(i18n.tr("mon_auto"))
        self.mon_auto.setChecked(True)
        top.addWidget(self.mon_auto)
        top.addWidget(QLabel(i18n.tr("mon_interval")))
        self.mon_interval = QComboBox()
        self.mon_interval.addItems(["2", "5", "10"])
        self.mon_interval.currentIndexChanged.connect(self._mon_interval_changed)
        top.addWidget(self.mon_interval)
        refresh_btn = QPushButton(i18n.tr("stat_refresh"))
        refresh_btn.clicked.connect(self.refresh_monitor)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        form = QFormLayout()
        self.mon_labels = {}
        for key in ("mon_cpu", "mon_cores", "mon_ram", "mon_battery",
                    "mon_temp", "mon_load", "mon_uptime"):
            label = QLabel("—")
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.mon_labels[key] = label
            form.addRow(i18n.tr(key), label)
        layout.addLayout(form)

        hint = QLabel(i18n.tr("mon_hint"))
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch(1)

        self.mon_timer = QTimer(self)
        self.mon_timer.setInterval(2000)
        self.mon_timer.timeout.connect(self._mon_tick)
        self.mon_timer.start()
        return page

    def _mon_interval_changed(self, index):
        self.mon_timer.setInterval((2000, 5000, 10000)[max(0, min(index, 2))])

    def _mon_tick(self):
        if not self.mon_auto.isChecked():
            return
        if self.tabs.currentWidget() is not self._monitor_page:
            return
        self.refresh_monitor()

    def _maybe_monitor(self, index):
        """При открытии вкладки «Монитор» — сразу обновить показатели."""
        if self.tabs.widget(index) is self._monitor_page:
            self.refresh_monitor()

    def refresh_monitor(self):
        if self._mon_busy:
            return
        self._mon_busy = True
        self._run(self._on_monitor, adb_actions.read_monitor, self.ip)

    def _on_monitor(self, mon, exc):
        self._mon_busy = False
        if exc:
            self._mon_fails += 1
            if self._mon_fails >= 3 and self.mon_auto.isChecked():
                self.mon_auto.setChecked(False)   # не молотим по мёртвому ADB
            self._failed(exc)
            return
        self._mon_fails = 0
        mon = mon or {}

        cpu = mon.get("cpu") or {}
        prev = self._prev_cpu or {}
        self._prev_cpu = cpu

        def pct(cur, old):
            if not cur or not old:
                return None
            d_busy = cur[0] - old[0]
            d_total = cur[1] - old[1]
            if d_total <= 0 or d_busy < 0:
                return None
            return int(round(100 * d_busy / d_total))

        overall = pct(cpu.get("overall"), prev.get("overall"))
        self.mon_labels["mon_cpu"].setText(
            i18n.tr("hw_pct_fmt", v=overall) if overall is not None else "—")

        freqs = mon.get("freqs") or {}
        prev_cores = prev.get("cores") or {}
        parts = []
        for core in sorted(cpu.get("cores") or {}):
            load = pct(cpu["cores"][core], prev_cores.get(core))
            text = f"cpu{core}: " + (i18n.tr("hw_pct_fmt", v=load)
                                     if load is not None else "—")
            if core in freqs:
                text += f" · {_hw_freq(freqs[core])}"
            parts.append(text)
        self.mon_labels["mon_cores"].setText(" · ".join(parts) or "—")

        memory = mon.get("memory") or {}
        self.mon_labels["mon_ram"].setText(
            i18n.tr("mon_ram_fmt", total=_hw_size(memory.get("total_mb")),
                    used=i18n.tr("hw_pct_fmt", v=memory["used_pct"]))
            if memory.get("used_pct") is not None else "—")

        battery = mon.get("battery") or {}
        if battery.get("level") is not None:
            charging = i18n.tr("stat_charging") if battery.get("charging") \
                else i18n.tr("stat_discharging")
            extra = ""
            if battery.get("temp_c") is not None:
                extra += f", {i18n.tr('hw_temp_fmt', v=battery['temp_c'])}"
            if battery.get("voltage_mv"):
                extra += f", {i18n.tr('hw_mv_fmt', v=battery['voltage_mv'])}"
            self.mon_labels["mon_battery"].setText(i18n.tr(
                "stat_battery_fmt", level=battery["level"],
                charging=charging, extra=extra))
        else:
            self.mon_labels["mon_battery"].setText("—")

        zones = sorted(mon.get("thermal") or [],
                       key=lambda z: -z["temp_c"])[:4]
        self.mon_labels["mon_temp"].setText(
            " · ".join(f"{_hw_tz_label(z['type']) or z['type']}: "
                       f"{i18n.tr('hw_temp_fmt', v=z['temp_c'])}"
                       for z in zones) or "—")

        load = mon.get("load") or {}
        self.mon_labels["mon_load"].setText(
            i18n.tr("stat_load_fmt", l1=load["l1"], l5=load["l5"],
                    l15=load["l15"]) if load else "—")

        uptime = mon.get("uptime_sec")
        if uptime:
            days, rest = divmod(int(uptime), 86400)
            hours, minutes = divmod(rest // 60, 60)
            self.mon_labels["mon_uptime"].setText(i18n.tr(
                "stat_uptime_fmt", days=days, hours=hours, minutes=minutes))
        else:
            self.mon_labels["mon_uptime"].setText("—")
        self._idle()

    # ------------------------------------------------------------ таб: Настройки
    def _tab_settings(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        dev_box = QGroupBox(i18n.tr("dev_group"))
        dev_form = QVBoxLayout(dev_box)
        cur_row = QHBoxLayout()
        cur_row.addWidget(QLabel(i18n.tr("dev_current")))
        self.dev_value_label = QLabel("—")
        self.dev_value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cur_row.addWidget(self.dev_value_label, 1)
        dev_form.addLayout(cur_row)
        hint = QLabel(i18n.tr("dev_hint"))
        hint.setWordWrap(True)
        dev_form.addWidget(hint)
        btn_row = QHBoxLayout()
        self.dev_enable_btn = QPushButton(i18n.tr("dev_enable"))
        self.dev_enable_btn.clicked.connect(lambda: self._toggle_dev(True))
        btn_row.addWidget(self.dev_enable_btn)
        self.dev_disable_btn = QPushButton(i18n.tr("dev_disable"))
        self.dev_disable_btn.clicked.connect(lambda: self._toggle_dev(False))
        btn_row.addWidget(self.dev_disable_btn)
        self.dev_refresh_btn = QPushButton(i18n.tr("dev_refresh"))
        self.dev_refresh_btn.clicked.connect(self.refresh_dev_mode)
        btn_row.addWidget(self.dev_refresh_btn)
        self.dev_open_btn = QPushButton(i18n.tr("dev_open_menu"))
        self.dev_open_btn.clicked.connect(self._open_dev_menu)
        btn_row.addWidget(self.dev_open_btn)
        btn_row.addStretch(1)
        dev_form.addLayout(btn_row)
        layout.addWidget(dev_box)

        pdns_box = QGroupBox(i18n.tr("pdns_group"))
        pdns_form = QVBoxLayout(pdns_box)
        pdns_cur = QHBoxLayout()
        pdns_cur.addWidget(QLabel(i18n.tr("pdns_current")))
        self.pdns_value_label = QLabel("—")
        self.pdns_value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        pdns_cur.addWidget(self.pdns_value_label, 1)
        pdns_form.addLayout(pdns_cur)
        pdns_hint = QLabel(i18n.tr("pdns_hint"))
        pdns_hint.setWordWrap(True)
        pdns_form.addWidget(pdns_hint)
        pdns_row = QHBoxLayout()
        self.pdns_mode = QComboBox()
        for label_key, mode in (("pdns_mode_off", "off"),
                                ("pdns_mode_opp", "opportunistic"),
                                ("pdns_mode_host", "hostname")):
            self.pdns_mode.addItem(i18n.tr(label_key), mode)
        self.pdns_mode.currentIndexChanged.connect(self._pdns_mode_changed)
        pdns_row.addWidget(self.pdns_mode)
        self.pdns_host = QLineEdit()
        self.pdns_host.setPlaceholderText("dns.adguard.com")
        pdns_row.addWidget(self.pdns_host, 1)
        pdns_form.addLayout(pdns_row)
        pdns_btns = QHBoxLayout()
        self.pdns_apply_btn = QPushButton(i18n.tr("pdns_apply"))
        self.pdns_apply_btn.clicked.connect(self._pdns_apply)
        pdns_btns.addWidget(self.pdns_apply_btn)
        self.pdns_refresh_btn = QPushButton(i18n.tr("pdns_refresh"))
        self.pdns_refresh_btn.clicked.connect(self._pdns_refresh)
        pdns_btns.addWidget(self.pdns_refresh_btn)
        pdns_btns.addStretch(1)
        pdns_form.addLayout(pdns_btns)
        layout.addWidget(pdns_box)

        set_box = QGroupBox(i18n.tr("set_group"))
        set_form = QVBoxLayout(set_box)
        ns_row = QHBoxLayout()
        ns_row.addWidget(QLabel(i18n.tr("set_ns")))
        self.set_ns = QComboBox()
        for ns in adb_actions.SETTING_NAMESPACES:
            self.set_ns.addItem(ns, ns)
        ns_row.addWidget(self.set_ns)
        ns_row.addWidget(QLabel(i18n.tr("set_key")))
        self.set_key_input = QLineEdit()
        self.set_key_input.setPlaceholderText(adb_actions.DEV_SETTINGS_KEY)
        ns_row.addWidget(self.set_key_input, 1)
        set_form.addLayout(ns_row)

        val_row = QHBoxLayout()
        val_row.addWidget(QLabel(i18n.tr("set_value")))
        self.set_value_input = QLineEdit()
        self.set_value_input.setPlaceholderText("1")
        val_row.addWidget(self.set_value_input, 1)
        self.set_get_btn = QPushButton(i18n.tr("set_get_btn"))
        self.set_get_btn.clicked.connect(self._setting_get)
        val_row.addWidget(self.set_get_btn)
        self.set_put_btn = QPushButton(i18n.tr("set_put_btn"))
        self.set_put_btn.clicked.connect(self._setting_put)
        val_row.addWidget(self.set_put_btn)
        set_form.addLayout(val_row)

        self.settings_output = QPlainTextEdit()
        self.settings_output.setReadOnly(True)
        self.settings_output.setPlaceholderText(i18n.tr("set_placeholder"))
        set_form.addWidget(self.settings_output, 1)
        layout.addWidget(set_box)
        self.settings_output.setMinimumHeight(140)
        layout.addStretch(1)

        # Прокрутка на случай маленького окна (блоков стало больше).
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        outer = QWidget()
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.addWidget(scroll)
        return outer

    def _maybe_load_settings(self, index):
        """Значения флагов читаются при первом открытии вкладки, а не при
        старте диалога — лишние соединения только по запросу."""
        if self.tabs.widget(index) is self._settings_page:
            if not self._dev_loaded:
                self.refresh_dev_mode()
            if not self._pdns_loaded:
                self._pdns_refresh()

    def refresh_dev_mode(self):
        self._busy()
        self._run(self._on_dev_value, adb_actions.get_setting,
                  self.ip, "global", adb_actions.DEV_SETTINGS_KEY)

    def _on_dev_value(self, value, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self._dev_loaded = True
        text = (value or "").strip()
        if text == "null":
            shown = i18n.tr("dev_value_null")
        elif text == "1":
            shown = i18n.tr("dev_value_on")
        elif text == "0":
            shown = i18n.tr("dev_value_off")
        else:
            shown = text or "—"
        self.dev_value_label.setText(shown)

    def _toggle_dev(self, enable):
        self.dev_enable_btn.setEnabled(False)
        self.dev_disable_btn.setEnabled(False)
        self._busy()
        self._run(lambda value, exc: self._on_dev_toggled(enable, value, exc),
                  adb_actions.set_developer_mode, self.ip, enable)

    def _on_dev_toggled(self, enable, value, exc):
        self.dev_enable_btn.setEnabled(True)
        self.dev_disable_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._on_dev_value(value, None)
        self.status.setText(i18n.tr("dev_enable_ok" if enable
                                    else "dev_disable_ok"))

    def _open_dev_menu(self):
        self.dev_open_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_dev_menu(out, exc),
                  adb_actions.open_developer_settings, self.ip)

    def _on_dev_menu(self, output, exc):
        self.dev_open_btn.setEnabled(True)
        self._append_settings("$ am start -a " + adb_actions.DEV_SETTINGS_ACTION,
                              "" if exc else (output or ""))
        if exc:
            self._failed(exc)
            return
        self.status.setText(i18n.tr("dev_opened"))

    def _setting_get(self):
        key = self.set_key_input.text().strip()
        if not key:
            self.status.setText(i18n.tr("set_key_required"))
            return
        ns = self.set_ns.currentData()
        self.set_get_btn.setEnabled(False)
        self._busy()
        self._run(lambda value, exc: self._on_setting_get(ns, key, value, exc),
                  adb_actions.get_setting, self.ip, ns, key)

    def _on_setting_get(self, ns, key, value, exc):
        self.set_get_btn.setEnabled(True)
        command = f"$ settings get {ns} {key}"
        if exc:
            self._append_settings(command, "")
            self._failed(exc)
            return
        self._idle()
        self._append_settings(command, (value or "").strip())
        self.status.setText(i18n.tr("set_get_done", ns=ns, name=key,
                                    value=(value or "").strip() or "—"))
        if ns == "global" and key == adb_actions.DEV_SETTINGS_KEY:
            self._on_dev_value(value, None)

    def _setting_put(self):
        key = self.set_key_input.text().strip()
        if not key:
            self.status.setText(i18n.tr("set_key_required"))
            return
        ns = self.set_ns.currentData()
        value = self.set_value_input.text()
        self.set_put_btn.setEnabled(False)
        self._busy()
        self._run(lambda shown, exc: self._on_setting_put(ns, key, value,
                                                          shown, exc),
                  self._put_and_verify, ns, key, value)

    def _put_and_verify(self, ns, key, value):
        """Запись + контрольное чтение (в фоновом потоке)."""
        adb_actions.put_setting(self.ip, ns, key, value)
        return adb_actions.get_setting(self.ip, ns, key)

    def _on_setting_put(self, ns, key, value, shown, exc):
        self.set_put_btn.setEnabled(True)
        command = f"$ settings put {ns} {key} {value}".rstrip()
        if exc:
            self._append_settings(command, "")
            self._failed(exc)
            return
        self._idle()
        self._append_settings(
            command,
            i18n.tr("set_put_done", ns=ns, name=key,
                    value=(shown or "").strip() or "—"))
        self.status.setText(i18n.tr("set_put_done", ns=ns, name=key,
                                    value=(shown or "").strip() or "—"))
        if ns == "global" and key == adb_actions.DEV_SETTINGS_KEY:
            self._on_dev_value(shown, None)

    def _append_settings(self, command, output):
        """Транскрипт команды в поле вывода вкладки настроек."""
        box = self.settings_output
        box.appendPlainText(command)
        box.appendPlainText(output.rstrip() or i18n.tr("shell_empty"))
        box.appendPlainText("")

    # ------------------------------------------------------- Private DNS
    def _pdns_refresh(self):
        self.pdns_refresh_btn.setEnabled(False)
        self._busy()
        self._run(self._on_pdns, adb_actions.private_dns_get, self.ip)

    def _on_pdns(self, value, exc):
        self.pdns_refresh_btn.setEnabled(True)
        self._pdns_loaded = True
        if exc:
            self._failed(exc)
            return
        self._idle()
        self._show_pdns(value or {})

    @staticmethod
    def _pdns_mode_label(mode):
        key = {"off": "pdns_mode_off", "opportunistic": "pdns_mode_opp",
               "hostname": "pdns_mode_host"}.get(mode)
        if key:
            return i18n.tr(key)
        return i18n.tr("pdns_mode_null") if mode == "null" else mode

    def _show_pdns(self, value):
        mode = (value or {}).get("mode", "null")
        hostname = (value or {}).get("hostname", "")
        index = self.pdns_mode.findData(mode)
        if index >= 0:
            self.pdns_mode.setCurrentIndex(index)
        self.pdns_host.setText(hostname)
        shown = self._pdns_mode_label(mode)
        if hostname:
            shown += " → " + hostname
        self.pdns_value_label.setText(shown)

    def _pdns_mode_changed(self, _index):
        self.pdns_host.setEnabled(self.pdns_mode.currentData() == "hostname")

    def _pdns_apply(self):
        mode = self.pdns_mode.currentData() or "off"
        hostname = self.pdns_host.text().strip()
        if mode == "hostname" and not hostname:
            self.status.setText(i18n.tr("pdns_host_required"))
            return
        self.pdns_apply_btn.setEnabled(False)
        self._busy()
        self._run(lambda value, exc: self._on_pdns_set(value, exc),
                  adb_actions.private_dns_set, self.ip, mode, hostname)

    def _on_pdns_set(self, value, exc):
        self.pdns_apply_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self._show_pdns(value or {})
        self.status.setText(i18n.tr("pdns_done"))

    def refresh_stats(self):
        self._busy()
        self._run(self._on_stats, adb_actions.read_stats, self.ip)

    def _on_stats(self, stats, exc):
        if exc:
            self._failed(exc)
            for label in self.stat_labels.values():
                label.setText("—")
            return
        self._idle()
        stats = stats or {}
        battery = stats.get("battery") or {}
        if battery.get("level") is not None:
            charging = i18n.tr("stat_charging") if battery.get("charging") \
                else i18n.tr("stat_discharging")
            temp = battery.get("temp_c")
            temp_text = f", {temp} °C" if temp is not None else ""
            self.stat_labels["stat_battery"].setText(
                i18n.tr("stat_battery_fmt", level=battery["level"],
                        charging=charging, extra=temp_text))
        else:
            self.stat_labels["stat_battery"].setText("—")
        memory = stats.get("memory") or {}
        self.stat_labels["stat_memory"].setText(
            i18n.tr("stat_memory_fmt", total=memory.get("total_mb", "?"),
                    used=memory.get("used_pct", "?")) if memory else "—")
        disk = stats.get("disk") or {}
        self.stat_labels["stat_disk"].setText(
            i18n.tr("stat_disk_fmt", total=disk.get("total_mb", "?"),
                    used=disk.get("used_pct", "?"),
                    mount=disk.get("mount", "?")) if disk else "—")
        display = stats.get("display") or {}
        if display:
            size = display.get("size", "?")
            if display.get("override_size"):
                size = f"{size} → {display['override_size']}"
            density = display.get("density", "?")
            if display.get("override_density"):
                density = f"{density} → {display['override_density']}"
            self.stat_labels["stat_display"].setText(
                i18n.tr("stat_display_fmt", size=size, density=density))
        else:
            self.stat_labels["stat_display"].setText("—")
        thermal = stats.get("thermal") or {}
        if thermal.get("temp_c") is not None:
            self.stat_labels["stat_thermal"].setText(
                i18n.tr("stat_thermal_fmt", temp=thermal["temp_c"]))
        else:
            self.stat_labels["stat_thermal"].setText("—")
        load = stats.get("load") or {}
        if load:
            self.stat_labels["stat_load"].setText(i18n.tr(
                "stat_load_fmt", l1=load["l1"], l5=load["l5"], l15=load["l15"]))
        else:
            self.stat_labels["stat_load"].setText("—")
        uptime = stats.get("uptime_sec")
        if uptime:
            days, rest = divmod(int(uptime), 86400)
            hours, minutes = divmod(rest // 60, 60)
            self.stat_labels["stat_uptime"].setText(
                i18n.tr("stat_uptime_fmt", days=days, hours=hours, minutes=minutes))
        else:
            self.stat_labels["stat_uptime"].setText("—")
        self.stat_labels["stat_device_ip"].setText(stats.get("device_ip") or "—")
        self._update_root_label()

    def _on_root_info(self, info, exc):
        if exc:
            self._failed(exc)
            return
        self._root_info = info or {}
        self._update_root_label()
        self._update_risk()

    def _update_root_label(self):
        if not self._root_info:
            return
        uid = self._root_info.get("uid")
        user = self._root_info.get("user", "?")
        if uid is not None:
            root_note = " — ROOT!" if uid == 0 else ""
            self.stat_labels["stat_root"].setText(
                f"uid={uid} ({user}){root_note} | su: "
                + (self._root_info.get("su_path") or "—"))
        if hasattr(self, "shell_su"):
            su_found = bool(self._root_info.get("su_found"))
            self.shell_su.setEnabled(su_found)
            self.shell_su.setToolTip("" if su_found else i18n.tr("shell_su_none"))

    def _update_risk(self):
        """Риск-бейдж: live-данные + свойства из последнего опроса."""
        info = self._root_info
        risk = adb_actions.assess_risk(
            self.device.extras,
            uid=info.get("uid"),
            adb_secure=info.get("adb_secure", ""),
            su_found=bool(info.get("su_found")),
            security_patch=info.get("security_patch", ""),
            sdk=info.get("sdk", ""),
            android_version=info.get("android_version", ""))
        color = RISK_COLORS.get(risk["level"], "#888888")
        level_text = i18n.tr("risk_level_" + risk["level"])
        self.risk_label.setStyleSheet(
            f"color: {color}; font-weight: 600;"
            if is_dark_theme() else f"color: {color}; font-weight: 600;")
        lines = [i18n.tr("risk_line", level=level_text, score=risk["score"])]
        lines += ["• " + i18n.tr(key) for key in risk["findings"]]
        if risk["recommendations"]:
            lines.append("")
            lines += ["→ " + i18n.tr(key) for key in risk["recommendations"]]
        self.risk_label.setText("\n".join(lines))

    def _reboot(self, mode):
        answer = QMessageBox.question(
            self, i18n.tr("confirm_title"),
            i18n.tr("reboot_question", ip=self.ip,
                    mode=i18n.tr("reboot_" + (mode or "normal"))),
            QMessageBox.Yes | QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self._busy()
        self._run(lambda ok, exc: self._on_reboot(exc),
                  adb_actions.reboot, self.ip, mode)

    def _on_reboot(self, exc):
        if exc:
            self._failed(exc)
        else:
            self.status.setText(i18n.tr("reboot_sent"))

    # ------------------------------------------------------------- экран (wm)
    def _wm_apply(self, kind):
        value = getattr(self, f"screen_{kind}_input").text().strip()
        if not value:
            self.status.setText(i18n.tr("screen_value_required"))
            return
        self._wm_set(kind, value)

    def _wm_reset(self, kind):
        self._wm_set(kind, "reset")

    def _wm_set(self, kind, value):
        for btn in self._wm_buttons[kind]:
            btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_wm_done(kind, value, out, exc),
                  self._wm_fn[kind], self.ip, value)

    def _on_wm_done(self, kind, value, _out, exc):
        for btn in self._wm_buttons[kind]:
            btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.status.setText(i18n.tr("screen_done", cmd=kind, value=value))
        self.refresh_stats()

    # ------------------------------------------------------------ таб: Действия
    def _tab_actions(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        layout = QVBoxLayout(inner)

        net_box = QGroupBox(i18n.tr("act_group_net"))
        grid = QGridLayout(net_box)
        self._act_toggles = {}
        for row, (service, label_key) in enumerate((
                ("wifi", "act_wifi"), ("data", "act_data"),
                ("bluetooth", "act_bt"), ("airplane", "act_airplane"))):
            grid.addWidget(QLabel(i18n.tr(label_key)), row, 0)
            state = QLabel("—")
            state.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(state, row, 1)
            on_btn = QPushButton(i18n.tr("act_enable"))
            on_btn.clicked.connect(
                lambda _=False, s=service: self._act_toggle(s, True))
            grid.addWidget(on_btn, row, 2)
            off_btn = QPushButton(i18n.tr("act_disable"))
            off_btn.clicked.connect(
                lambda _=False, s=service: self._act_toggle(s, False))
            grid.addWidget(off_btn, row, 3)
            self._act_toggles[service] = (state, on_btn, off_btn)
        hint = QLabel(i18n.tr("act_net_hint"))
        hint.setWordWrap(True)
        grid.addWidget(hint, grid.rowCount(), 0, 1, 4)
        layout.addWidget(net_box)

        screen_box = QGroupBox(i18n.tr("act_group_screen"))
        grid2 = QGridLayout(screen_box)
        sleep_btn = QPushButton(i18n.tr("act_sleep"))
        sleep_btn.clicked.connect(lambda _=False: self._send_key("sleep"))
        grid2.addWidget(sleep_btn, 0, 0)
        wake_btn = QPushButton(i18n.tr("act_wakeup"))
        wake_btn.clicked.connect(lambda _=False: self._send_key("wakeup"))
        grid2.addWidget(wake_btn, 0, 1)
        self.stayon_check = QCheckBox(i18n.tr("act_stayon"))
        self.stayon_check.toggled.connect(self._act_stayon)
        grid2.addWidget(self.stayon_check, 0, 2)
        grid2.addWidget(QLabel(i18n.tr("act_brightness")), 1, 0)
        self.act_bright = QSpinBox()
        self.act_bright.setRange(5, 255)
        grid2.addWidget(self.act_bright, 1, 1)
        self.act_auto = QCheckBox(i18n.tr("act_auto"))
        grid2.addWidget(self.act_auto, 1, 2)
        apply_btn = QPushButton(i18n.tr("screen_apply"))
        apply_btn.clicked.connect(self._apply_brightness)
        grid2.addWidget(apply_btn, 1, 3)
        screen_hint = QLabel(i18n.tr("act_screen_hint"))
        screen_hint.setWordWrap(True)
        grid2.addWidget(screen_hint, 2, 0, 1, 4)
        layout.addWidget(screen_box)
        layout.addStretch(1)

        scroll.setWidget(inner)
        outer.addWidget(scroll)
        return page

    def _maybe_actions(self, index):
        """Состояние тумблеров читается при первом открытии вкладки."""
        if self.tabs.widget(index) is self._actions_page \
                and not self._act_loaded:
            self._act_loaded = True
            self.refresh_action_state()

    def refresh_action_state(self):
        self._run(self._on_action_state, adb_actions.read_action_state, self.ip)

    def _on_action_state(self, state, exc):
        if exc:
            return                    # фоновый опрос состояния: без диалогов
        state = state or {}
        for service, (state_lbl, _on, _off) in self._act_toggles.items():
            value = state.get(service)
            state_lbl.setText(
                i18n.tr("act_state_on") if value else
                i18n.tr("act_state_off") if value is False else "—")
        if state.get("brightness") is not None:
            self.act_bright.setValue(state["brightness"])
        if state.get("auto_brightness") is not None:
            self.act_auto.setChecked(state["auto_brightness"])

    def _act_toggle(self, service, enable):
        state_lbl, on_btn, off_btn = self._act_toggles[service]
        on_btn.setEnabled(False)
        off_btn.setEnabled(False)
        self._busy()
        fn = adb_actions.set_airplane if service == "airplane" \
            else adb_actions.service_toggle
        self._run(lambda _o, exc: self._on_act_toggle(service, exc),
                  fn, self.ip, enable)

    def _on_act_toggle(self, service, exc):
        _state_lbl, on_btn, off_btn = self._act_toggles[service]
        on_btn.setEnabled(True)
        off_btn.setEnabled(True)
        if exc:
            self._failed(exc)
        else:
            self.status.setText(i18n.tr("act_done"))
        self.refresh_action_state()

    def _act_stayon(self, enable):
        self._busy()
        self._run(lambda _o, exc: self._on_act_done(exc),
                  adb_actions.set_stayon, self.ip, enable)

    def _apply_brightness(self):
        self._busy()
        self._run(lambda _o, exc: self._on_act_done(exc),
                  adb_actions.set_brightness, self.ip, self.act_bright.value(),
                  self.act_auto.isChecked())

    def _on_act_done(self, exc):
        if exc:
            self._failed(exc)
        else:
            self.status.setText(i18n.tr("act_done"))

    # ------------------------------------------------------------ таб: Приложения
    def _tab_apps(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.addWidget(QLabel(i18n.tr("apps_kind")))
        self.apps_kind = QComboBox()
        self.apps_kind.addItem(i18n.tr("apps_kind_third"), "third")
        self.apps_kind.addItem(i18n.tr("apps_kind_system"), "system")
        self.apps_kind.addItem(i18n.tr("apps_kind_all"), "all")
        top.addWidget(self.apps_kind)
        self.apps_refresh_btn = QPushButton(i18n.tr("apps_refresh"))
        self.apps_refresh_btn.clicked.connect(self.refresh_apps)
        top.addWidget(self.apps_refresh_btn)
        self.apps_fav_btn = QPushButton(i18n.tr("fav_filter"))
        self.apps_fav_btn.setCheckable(True)
        self.apps_fav_btn.setToolTip(i18n.tr("fav_filter_hint"))
        self.apps_fav_btn.toggled.connect(lambda *_: self._filter_apps())
        top.addWidget(self.apps_fav_btn)
        top.addSpacing(12)
        top.addWidget(QLabel(i18n.tr("apps_search")))
        self.apps_search = QLineEdit()
        self.apps_search.setPlaceholderText(i18n.tr("apps_search_hint"))
        self.apps_search.setClearButtonEnabled(True)
        self.apps_search.textChanged.connect(self._filter_apps)
        top.addWidget(self.apps_search, 1)
        layout.addLayout(top)

        self.apps_tree = QTreeWidget()
        self.apps_tree.setHeaderLabels([i18n.tr("apps_col_pkg"),
                                        i18n.tr("apps_col_ver"),
                                        i18n.tr("apps_col_origin"),
                                        i18n.tr("apps_col_path")])
        self.apps_tree.setRootIsDecorated(False)
        self.apps_tree.setAlternatingRowColors(True)
        self.apps_tree.setSortingEnabled(True)
        self.apps_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.apps_tree.customContextMenuRequested.connect(self._apps_context_menu)
        self.apps_tree.header().resizeSection(0, 210)
        self.apps_tree.header().resizeSection(2, 90)
        self.apps_tree.itemDoubleClicked.connect(lambda *_: self._app_details())
        layout.addWidget(self.apps_tree, 1)

        actions = QHBoxLayout()
        for attr, handler in (("apps_run", self._app_launch),
                              ("apps_stop", self._app_stop),
                              ("apps_uninstall", self._app_uninstall),
                              ("apps_disable", self._app_disable),
                              ("apps_enable", self._app_enable),
                              ("apps_clear", self._app_clear)):
            btn = QPushButton(i18n.tr(attr))
            btn.clicked.connect(handler)
            actions.addWidget(btn)
        layout.addLayout(actions)

        actions2 = QHBoxLayout()
        details_btn = QPushButton(i18n.tr("apps_info"))
        details_btn.clicked.connect(self._app_details)
        actions2.addWidget(details_btn)
        self.apk_btn = QPushButton(i18n.tr("apps_apk_dl"))
        self.apk_btn.clicked.connect(self._app_apk)
        actions2.addWidget(self.apk_btn)
        self.install_btn = QPushButton(i18n.tr("apps_install"))
        self.install_btn.clicked.connect(self._install_apk)
        actions2.addWidget(self.install_btn)
        self.export_btn = QPushButton(i18n.tr("apps_export"))
        self.export_btn.clicked.connect(self._export_apps)
        self.export_btn.setToolTip(i18n.tr("apps_export_saving"))
        actions2.addWidget(self.export_btn)
        actions2.addStretch(1)
        layout.addLayout(actions2)
        return page

    def _apps_status_text(self, total: int) -> str:
        text = i18n.tr("apps_found", count=total)
        if not total:
            # Пусто — часто у pm на кривых прошивках: подсказываем, где
            # посмотреть сырой ответ (журнал) и что попробовать ещё раз
            text += " " + i18n.tr("apps_none_hint")
        return text

    def _filter_apps(self, _text=""):
        """Прячет строки: не совпал поиск и/или не в избранном."""
        needle = self.apps_search.text().strip().lower()
        fav_only = self.apps_fav_btn.isChecked()
        shown = 0
        total = self.apps_tree.topLevelItemCount()
        for index in range(total):
            item = self.apps_tree.topLevelItem(index)
            package = item.data(0, Qt.UserRole) or ""
            match = (not fav_only or package in self.fav_apps) and (
                not needle or any(
                    needle in (item.text(col) or "").lower()
                    for col in range(self.apps_tree.columnCount())))
            item.setHidden(not match)
            shown += match
        if needle:
            self.status.setText(i18n.tr("apps_filter_found",
                                        shown=shown, total=total))
        elif fav_only:
            self.status.setText(i18n.tr("apps_fav_count_fmt", count=shown))
        elif getattr(self, "_apps_total", None) is not None:
            # поиск очищен — возвращаем статус последнего обновления списка
            self.status.setText(self._apps_status_text(self._apps_total))

    def _apps_context_menu(self, pos):
        """Правый клик по списку: добавить/убрать приложение из избранного."""
        item = self.apps_tree.itemAt(pos)
        package = (item.data(0, Qt.UserRole) or "") if item else ""
        if not package:
            return
        menu = QMenu(self)
        in_favs = package in self.fav_apps
        action = menu.addAction(i18n.tr("fav_remove" if in_favs else "fav_add"))
        if menu.exec(self.apps_tree.viewport().mapToGlobal(pos)) is not action:
            return
        if favorites.toggle(favorites.APPS_KEY, package):
            self.fav_apps.add(package)
        else:
            self.fav_apps.discard(package)
        item.setText(0, ("★ " if package in self.fav_apps else "") + package)
        self.status.setText(i18n.tr(
            "fav_added" if package in self.fav_apps else "fav_removed",
            name=package))
        self._filter_apps()

    def refresh_apps(self):
        kind = self.apps_kind.currentData() or "third"
        self._busy()
        self.apps_refresh_btn.setEnabled(False)
        self._run(self._on_apps, adb_actions.list_apps, self.ip, kind)

    def _on_apps(self, apps, exc):
        self.apps_refresh_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.apps_tree.clear()
        origin_keys = {"system": "apps_origin_system",
                       "third": "apps_origin_third"}
        for app in apps or []:
            # version/path/origin пустые, если обогащение не добрало данных
            origin_key = origin_keys.get(app.get("origin", ""),
                                         "apps_origin_unknown")
            package = app["package"]
            starred = "★ " if package in self.fav_apps else ""
            item = NaturalTreeItem([starred + package, app.get("version") or "",
                                    i18n.tr(origin_key), app.get("path", "")])
            item.setData(0, Qt.UserRole, package)
            self.apps_tree.addTopLevelItem(item)
        self._apps_total = len(apps or [])
        self.status.setText(self._apps_status_text(self._apps_total))
        self._filter_apps()          # применяем активный поиск к новому списку

    # ------------------------------------------------------- выгрузка для ИИ
    def _export_apps(self):
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("apps_export"), "droidscout_apps.csv",
            "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        self.export_btn.setEnabled(False)
        self._busy("apps_export_saving")
        self._run(lambda count, exc: self._on_export(path, count, exc),
                  self._collect_and_export, self.ip, path)

    @staticmethod
    def _collect_and_export(host, path):
        """Полный список с устройства -> файл на ПК. Возвращает число пакетов.

        Выполняется в ActionWorker: подключений несколько, на кривых
        прошивках это может занять до минуты.
        """
        apps = adb_actions.collect_apps(host)
        if not apps:
            raise adb_actions.ActionError(
                "pm list вернул ноль пакетов (сырые ответы — в журнале)", "")
        if path.lower().endswith(".json"):
            exporter.export_apps_json(path, apps)
        else:
            exporter.export_apps_csv(path, apps)
        return len(apps)

    def _on_export(self, path, count, exc):
        self.export_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self.status.setText(i18n.tr("apps_export_saved", path=path, count=count))

    def _app_apk(self):
        """APK выбранного приложения -> файл на ПК (base + сплиты)."""
        item = self.apps_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("apps_select"))
            return
        package = item.data(0, Qt.UserRole) or item.text(0)
        # колонка «APK» — запасной путь на случай, если pm path молчит
        fallback = item.text(3)
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("apps_apk_dl"), f"{package}.apk",
            "APK (*.apk);;All files (*)")
        if not path:
            return
        self.apk_btn.setEnabled(False)
        self._busy("apps_apk_saving")
        self._run(lambda saved, exc: self._on_app_apk(path, saved, exc),
                  adb_actions.download_app_apk, self.ip, package, path,
                  fallback)

    def _on_app_apk(self, dest, saved, exc):
        self.apk_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        saved = saved or [dest]
        self.status.setText(i18n.tr("apps_apk_saved",
                                    count=len(saved), path=saved[0]))
        sha = _local_sha256(saved[0])
        if not sha:
            return
        QApplication.clipboard().setText(sha)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle(i18n.tr("apps_apk_dl"))
        box.setText(i18n.tr("apps_sha256_line", count=len(saved),
                            path=saved[0], sha=sha))
        vt_btn = box.addButton(i18n.tr("apps_vt_open"), QMessageBox.ActionRole)
        box.addButton(QMessageBox.Ok)
        box.exec()
        if box.clickedButton() is vt_btn:
            QDesktopServices.openUrl(QUrl(VT_URL + sha))

    def _selected_package(self):
        item = self.apps_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("apps_select"))
            return ""
        return item.data(0, Qt.UserRole)

    def _app_act(self, action, confirm_key=None):
        package = self._selected_package()
        if not package:
            return
        if confirm_key:
            answer = QMessageBox.question(
                self, i18n.tr("confirm_title"),
                i18n.tr(confirm_key, pkg=package),
                QMessageBox.Yes | QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        self._busy()
        self._run(lambda out, exc: self._on_app_action(out, exc),
                  adb_actions.app_action, self.ip, package, action)

    def _on_app_action(self, output, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.status.setText(i18n.tr("apps_done",
                                    output=(output or "").strip().splitlines()[-1]
                                    if (output or "").strip() else "OK"))

    def _app_launch(self):
        self._app_act("launch")

    def _app_stop(self):
        self._app_act("stop")

    def _app_uninstall(self):
        self._app_act("uninstall", "apps_confirm_uninstall")

    def _app_disable(self):
        self._app_act("disable", "apps_confirm_disable")

    def _app_enable(self):
        self._app_act("enable")

    def _app_clear(self):
        self._app_act("clear", "apps_confirm_clear")

    def _app_details(self):
        package = self._selected_package()
        if not package:
            return
        item = self.apps_tree.currentItem()
        fallback = item.text(3) if item else ""
        self._busy()
        self._run(lambda out, exc: self._on_app_details(package, out, exc),
                  adb_actions.app_details, self.ip, package,
                  fallback_path=fallback)

    def _on_app_details(self, package, details, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        details = details or {}
        state = i18n.tr("apps_stopped")
        if details.get("running"):
            state = i18n.tr("apps_running", pid=details.get("pid") or "?")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle(i18n.tr("apps_details_title", pkg=package))
        box.setText(i18n.tr(
            "apps_details_fmt",
            version=details.get("version", "—"),
            code=details.get("code", "—"),
            installed=details.get("installed", "—"),
            updated=details.get("updated", "—"),
            sdk=details.get("target_sdk", "—"),
            path=details.get("path", "—"),
            state=state,
            sha256=details.get("sha256") or "—"))
        vt_btn = None
        if details.get("sha256"):
            vt_btn = box.addButton(i18n.tr("apps_vt_open"),
                                   QMessageBox.ActionRole)
        box.addButton(QMessageBox.Ok)
        box.exec()
        if vt_btn is not None and box.clickedButton() is vt_btn:
            QDesktopServices.openUrl(QUrl(VT_URL + details["sha256"]))

    def _install_apk(self):
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("apps_install"), os.path.expanduser("~"),
            "APK (*.apk);;All files (*)")
        if not path:
            return
        self.install_btn.setEnabled(False)
        self._busy("apps_installing")
        self._run_with_progress(
            "apps_installing", "progress_transfer_fmt",
            lambda out, exc: self._on_install(out, exc),
            adb_actions.install_apk, self.ip, path,
            finish_busy=True)

    def _on_install(self, output, exc):
        self.install_btn.setEnabled(True)
        self._close_progress()
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.status.setText(i18n.tr("apps_install_done",
                                    output=(output or "").strip()[:200] or "OK"))

    # ---------------------------------------------------------------- таб: Пульт
    def _tab_remote(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        grid_box = QGroupBox(i18n.tr("remote_group"))
        grid = QGridLayout(grid_box)
        grid.setSpacing(6)

        def key_button(text, key, min_width=0):
            btn = QPushButton(text)
            btn.setMinimumHeight(34)
            if min_width:
                btn.setMinimumWidth(min_width)
            btn.clicked.connect(lambda _=False, k=key: self._send_key(k))
            return btn

        grid.addWidget(key_button(i18n.tr("remote_power"), "power"), 0, 0)
        grid.addWidget(key_button("Vol +", "vol_up"), 0, 1)
        grid.addWidget(key_button("Vol −", "vol_down"), 0, 2)
        grid.addWidget(key_button(i18n.tr("remote_mute"), "mute"), 0, 3)

        grid.addWidget(QLabel(""), 1, 0)
        grid.addWidget(key_button("▲", "up"), 1, 1)
        grid.addWidget(QLabel(""), 1, 2)
        grid.addWidget(key_button(i18n.tr("remote_menu"), "menu"), 1, 3)

        grid.addWidget(key_button("◀", "left"), 2, 0)
        grid.addWidget(key_button("OK", "ok", min_width=56), 2, 1)
        grid.addWidget(key_button("▶", "right"), 2, 2)
        grid.addWidget(key_button(i18n.tr("remote_play"), "play_pause"), 2, 3)

        grid.addWidget(QLabel(""), 3, 0)
        grid.addWidget(key_button("▼", "down"), 3, 1)
        grid.addWidget(QLabel(""), 3, 2)
        grid.addWidget(key_button(i18n.tr("remote_stop"), "stop"), 3, 3)

        grid.addWidget(key_button(i18n.tr("remote_home"), "home"), 4, 0)
        grid.addWidget(key_button(i18n.tr("remote_back"), "back"), 4, 1)
        grid.addWidget(key_button("◀◀", "rewind"), 4, 2)
        grid.addWidget(key_button("▶▶", "forward"), 4, 3)
        outer.addWidget(grid_box)

        text_row = QHBoxLayout()
        self.remote_text = QLineEdit()
        self.remote_text.setPlaceholderText(i18n.tr("remote_text_hint"))
        self.remote_text.returnPressed.connect(self._send_text)
        text_row.addWidget(self.remote_text, 1)
        send_btn = QPushButton(i18n.tr("remote_send"))
        send_btn.clicked.connect(self._send_text)
        text_row.addWidget(send_btn)
        outer.addLayout(text_row)
        outer.addStretch(1)
        return page

    def _send_key(self, key):
        self._busy()
        self._run(lambda _out, exc: self._on_key(exc),
                  adb_actions.send_key, self.ip, key)

    def _on_key(self, exc):
        if exc:
            self._failed(exc)
        else:
            self._idle()

    def _send_text(self):
        text = self.remote_text.text().strip()
        if not text:
            return
        self._busy()
        self._run(lambda _out, exc: self._on_key(exc),
                  adb_actions.send_text, self.ip, text)

    # ------------------------------------------------------------- таб: Скриншот
    def _tab_screenshot(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.shot_label = QLabel(i18n.tr("shot_placeholder"))
        self.shot_label.setAlignment(Qt.AlignCenter)
        self.shot_label.setMinimumSize(420, 260)
        layout.addWidget(self.shot_label, 1)

        row = QHBoxLayout()
        self.shot_btn = QPushButton(i18n.tr("shot_take"))
        self.shot_btn.clicked.connect(self.take_screenshot)
        row.addWidget(self.shot_btn)
        self.shot_save_btn = QPushButton(i18n.tr("shot_save"))
        self.shot_save_btn.setEnabled(False)
        self.shot_save_btn.clicked.connect(self.save_screenshot)
        row.addWidget(self.shot_save_btn)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    def take_screenshot(self):
        self.shot_btn.setEnabled(False)
        self._busy("shot_saving")
        self._run(lambda png, exc: self._on_shot(png, exc),
                  adb_actions.screenshot, self.ip)

    def _on_shot(self, png, exc):
        self.shot_btn.setEnabled(True)
        if exc:
            self.shot_save_btn.setEnabled(False)
            self._failed(exc)
            return
        self._idle()
        self._shot_png = png or b""
        image = QImage.fromData(self._shot_png)
        if not image.isNull():
            self.shot_label.setPixmap(QPixmap.fromImage(image).scaled(
                self.shot_label.width() or 420, self.shot_label.height() or 260,
                Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.shot_save_btn.setEnabled(bool(self._shot_png))
        self.status.setText(i18n.tr("shot_done"))

    def save_screenshot(self):
        if not self._shot_png:
            return
        default = os.path.join(
            os.path.expanduser("~"), "droidscout_"
            + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".png")
        path, _ = QFileDialog.getSaveFileName(self, i18n.tr("shot_save"),
                                              default, "PNG (*.png)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self._shot_png)
            self.status.setText(i18n.tr("shot_saved", path=path))
        except OSError as exc:
            self.status.setText(i18n.tr("toolkit_error", error=str(exc)[:200]))

    # --------------------------------------------------------------- таб: Файлы
    QUICK_DIRS = ("/system", "/vendor", "/data", "/data/local/tmp", "/sdcard")

    def _tab_files(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.addWidget(QLabel(i18n.tr("files_path")))
        self.files_path = QLineEdit("/")
        self.files_path.returnPressed.connect(self.refresh_files)
        top.addWidget(self.files_path, 1)
        self.files_up_btn = QPushButton(i18n.tr("files_up"))
        self.files_up_btn.clicked.connect(self._files_up)
        top.addWidget(self.files_up_btn)
        self.files_refresh_btn = QPushButton(i18n.tr("files_refresh"))
        self.files_refresh_btn.clicked.connect(self.refresh_files)
        top.addWidget(self.files_refresh_btn)
        layout.addLayout(top)

        quick = QHBoxLayout()
        quick.addWidget(QLabel(i18n.tr("files_quick")))
        for place in self.QUICK_DIRS:
            btn = QPushButton(place)
            btn.clicked.connect(lambda _=False, p=place: self._files_goto(p))
            quick.addWidget(btn)
        quick.addStretch(1)
        layout.addLayout(quick)

        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels([i18n.tr("files_col_name"),
                                         i18n.tr("files_col_perms"),
                                         i18n.tr("files_col_size"),
                                         i18n.tr("files_col_date")])
        self.files_tree.setRootIsDecorated(False)
        self.files_tree.setAlternatingRowColors(True)
        self.files_tree.setSortingEnabled(True)
        self.files_tree.header().resizeSection(0, 280)
        self.files_tree.header().resizeSection(1, 110)
        self.files_tree.header().resizeSection(2, 80)
        self.files_tree.itemDoubleClicked.connect(self._files_open)
        layout.addWidget(self.files_tree, 1)

        actions = QHBoxLayout()
        self.files_download_btn = QPushButton(i18n.tr("files_download"))
        self.files_download_btn.clicked.connect(self._file_download)
        actions.addWidget(self.files_download_btn)
        self.files_upload_btn = QPushButton(i18n.tr("files_upload"))
        self.files_upload_btn.clicked.connect(self._file_upload)
        actions.addWidget(self.files_upload_btn)
        self.apk_paths_btn = QPushButton(i18n.tr("apk_paths_btn"))
        self.apk_paths_btn.clicked.connect(self._apk_paths)
        actions.addWidget(self.apk_paths_btn)
        actions.addStretch(1)
        layout.addLayout(actions)
        return page

    def _apk_paths(self):
        """«Куда закачать APK?» — скан ФС и диалог с рекомендациями."""
        self.apk_paths_btn.setEnabled(False)
        self._busy("apk_paths_busy")
        self._run(self._on_apk_paths, adb_actions.scan_apk_targets, self.ip)

    def _on_apk_paths(self, targets, exc):
        self.apk_paths_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        dlg = QDialog(self)
        dlg.setWindowTitle(i18n.tr("apk_paths_title"))
        dlg.resize(640, 400)
        lay = QVBoxLayout(dlg)
        hint = QLabel(i18n.tr("apk_paths_hint"))
        hint.setWordWrap(True)
        lay.addWidget(hint)

        tree = QTreeWidget()
        tree.setHeaderLabels([i18n.tr("apk_paths_col_path"),
                              i18n.tr("apk_paths_col_status"),
                              i18n.tr("apk_paths_col_free")])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        tree.setSortingEnabled(True)
        tree.header().resizeSection(0, 290)
        tree.header().resizeSection(1, 240)
        for target in targets or []:
            free = target.get("free_bytes")
            item = NaturalTreeItem([
                target.get("path", ""),
                i18n.tr("apk_paths_" + target.get("tier", "no")),
                _human_mb(free) if free is not None else "—"])
            item.setData(0, Qt.UserRole, target.get("path", ""))
            if free is not None:
                item.setData(2, Qt.UserRole, free)   # числовая сортировка
            tree.addTopLevelItem(item)
        lay.addWidget(tree, 1)

        row = QHBoxLayout()
        pick_btn = QPushButton(i18n.tr("apk_paths_pick"))
        pick_btn.setEnabled(False)
        pick_btn.clicked.connect(lambda: self._use_apk_path(dlg, tree))
        row.addWidget(pick_btn)
        row.addStretch(1)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(dlg.reject)
        row.addWidget(close_btn)
        lay.addLayout(row)

        def _selection_changed(*_args):
            pick_btn.setEnabled(tree.currentItem() is not None)

        tree.currentItemChanged.connect(_selection_changed)
        tree.itemDoubleClicked.connect(lambda *_a: self._use_apk_path(dlg, tree))
        dlg.exec()

    def _use_apk_path(self, dlg, tree):
        item = tree.currentItem()
        if not item:
            return
        dlg.accept()
        self._files_goto(item.data(0, Qt.UserRole) or "/")

    def _files_join(self, name: str) -> str:
        base = self.files_path.text().strip() or "/"
        return base + name if base == "/" else base.rstrip("/") + "/" + name

    def refresh_files(self):
        self._busy()
        self.files_refresh_btn.setEnabled(False)
        self._run(self._on_files, adb_actions.list_dir, self.ip,
                  self.files_path.text().strip() or "/")

    def _on_files(self, listing, exc):
        self.files_refresh_btn.setEnabled(True)
        if exc is not None:
            self._files_fallback(exc)
            return
        self._idle()
        self._show_files(listing)

    def _show_files(self, listing, requested=""):
        """Заполняет таблицу файлов и пишет статус (с учётом перехода)."""
        self.files_tree.clear()
        entries = (listing or {}).get("entries", [])
        for entry in entries:
            label = entry["name"] + (f" -> {entry['target']}"
                                     if entry.get("target") else "")
            item = NaturalTreeItem([label, entry.get("perms", ""),
                                    entry.get("size", ""),
                                    entry.get("date", "")])
            item.setData(0, Qt.UserRole, entry)
            self.files_tree.addTopLevelItem(item)
        actual = (listing or {}).get("path", "")
        if requested and actual and \
                requested.rstrip("/") != actual.rstrip("/"):
            self.status.setText(i18n.tr("files_fallback",
                                        requested=requested, path=actual))
        else:
            self.status.setText(i18n.tr("files_listed", path=actual,
                                        count=len(entries)))

    def _files_fallback(self, exc):
        """«denied» на /storage/* — авто-переход на /sdcard и псевдонимы.

        На ТВ-боксах сам каталог /storage/emulated часто читает только
        root, а /storage/emulated/0 и /sdcard работают. Петли нет:
        list_dir_any обслуживается отдельным обработчиком, который при
        неудаче сразу показывает исходную подсказку про root.
        """
        if getattr(exc, "code", "") != "denied":
            self._failed(exc)
            return
        requested = self.files_path.text().strip() or "/"
        alts = adb_actions.storage_alternates(requested)
        if not alts:
            self._failed(exc)
            return
        self._busy("files_fallback_busy")
        self._run(self._on_files_alts(requested), adb_actions.list_dir_any,
                  self.ip, alts, requested=requested)

    def _on_files_alts(self, requested):
        def handler(listing, exc):
            if exc is not None:
                self._failed(exc)     # ни один псевдоним не открыт
                return
            self._idle()
            actual = (listing or {}).get("path") or requested
            self.files_path.setText(actual)
            self._show_files(listing, requested=requested)
        return handler

    def _files_goto(self, path: str):
        self.files_path.setText(path or "/")
        self.refresh_files()

    def _files_up(self):
        path = self.files_path.text().strip() or "/"
        parent = os.path.dirname(path.rstrip("/")) if path != "/" else ""
        self._files_goto(parent or "/")

    def _files_open(self, item, _column):
        entry = item.data(0, Qt.UserRole) or {}
        name = entry.get("name", "")
        if not name:
            return
        if entry.get("target"):          # симлинк на абсолютный путь
            target = entry["target"]
            if target.startswith("/"):
                self._files_goto(target)
                return
        if not entry.get("is_dir"):
            return
        self._files_goto(self._files_join(name))

    def _file_download(self):
        item = self.files_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("files_select"))
            return
        entry = item.data(0, Qt.UserRole) or {}
        if entry.get("is_dir"):
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("files_is_dir"))
            return
        remote = self._files_join(entry.get("name", "file"))
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("files_download"), entry.get("name", "file"),
            "All files (*)")
        if not path:
            return
        self.files_download_btn.setEnabled(False)
        self._busy("files_downloading")
        self._run(lambda data, exc: self._on_file_data(path, data, exc),
                  adb_actions.pull_file, self.ip, remote)

    def _on_file_data(self, path, data, exc):
        self.files_download_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        try:
            with open(path, "wb") as f:
                f.write(data or b"")
        except OSError as e:
            self._failed(adb_actions.ActionError(str(e), ""))
            return
        self.status.setText(i18n.tr("files_saved", path=path,
                                    count=len(data or b"")))

    def _file_upload(self):
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("files_upload"), os.path.expanduser("~"),
            "All files (*);;APK (*.apk)")
        if not path:
            return
        self.files_upload_btn.setEnabled(False)
        self._busy("files_uploading")
        self._run_with_progress(
            "files_uploading", "upload_transfer_fmt",
            lambda remote, exc: self._on_file_uploaded(remote, exc),
            adb_actions.push_file, self.ip, path,
            self.files_path.text().strip() or "/")

    def _on_file_uploaded(self, remote, exc):
        self.files_upload_btn.setEnabled(True)
        self._close_progress()
        if exc:
            self._failed(exc)
            return
        self.status.setText(i18n.tr("files_uploaded", path=remote))
        self.refresh_files()

    # --------------------------------------------------------------- таб: Консоль
    def _tab_shell(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.shell_output = QPlainTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setPlaceholderText(i18n.tr("shell_placeholder_out"))
        layout.addWidget(self.shell_output, 1)

        row = QHBoxLayout()
        self.shell_input = QLineEdit()
        self.shell_input.setPlaceholderText(i18n.tr("shell_hint"))
        self.shell_input.returnPressed.connect(self.run_shell)
        row.addWidget(self.shell_input, 1)
        self.shell_su = QCheckBox(i18n.tr("shell_su"))
        self.shell_su.setToolTip(i18n.tr("shell_su_none"))
        row.addWidget(self.shell_su)
        self.shell_run_btn = QPushButton(i18n.tr("shell_run"))
        self.shell_run_btn.clicked.connect(self.run_shell)
        row.addWidget(self.shell_run_btn)
        layout.addLayout(row)

        hint = QLabel(i18n.tr("shell_warning"))
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return page

    def run_shell(self):
        command = self.shell_input.text().strip()
        if not command:
            return
        sent = command
        if self.shell_su.isChecked():
            sent = "su -c " + adb_actions.shlex_quote(command)
        self._shell_history.append(command)
        self._shell_index = len(self._shell_history)
        self.shell_run_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_shell(out, exc),
                  adb_actions.shell, self.ip, sent)

    def _on_shell(self, output, exc):
        self.shell_run_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.shell_output.appendPlainText("$ " + (self._shell_history[-1]
                                                  if self._shell_history else ""))
        self.shell_output.appendPlainText(output.rstrip()
                                          or i18n.tr("shell_empty"))
        self.shell_output.appendPlainText("")

    def keyPressEvent(self, event):
        # история команд стрелками в консоли
        if self.tabs.currentWidget() is not None and \
                self.shell_input.hasFocus() and self._shell_history:
            if event.key() == Qt.Key_Up:
                self._shell_index = max(0, self._shell_index - 1)
                self.shell_input.setText(self._shell_history[self._shell_index])
                return
            if event.key() == Qt.Key_Down:
                self._shell_index = min(len(self._shell_history),
                                        self._shell_index + 1)
                text = (self._shell_history[self._shell_index]
                        if self._shell_index < len(self._shell_history) else "")
                self.shell_input.setText(text)
                return
        super().keyPressEvent(event)

    # --------------------------------------------------------------- таб: Логкат
    def _tab_logcat(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        row.addWidget(QLabel(i18n.tr("logcat_level")))
        self.logcat_level = QComboBox()
        for name, data in (("V", "V"), ("D", "D"), ("I", "I"),
                           ("W", "W"), ("E", "E")):
            self.logcat_level.addItem(name, data)
        self.logcat_level.setCurrentIndex(3)
        row.addWidget(self.logcat_level)
        row.addWidget(QLabel(i18n.tr("logcat_lines")))
        self.logcat_count = QSpinBox()
        self.logcat_count.setRange(50, 5000)
        self.logcat_count.setValue(300)
        self.logcat_count.setSingleStep(100)
        row.addWidget(self.logcat_count)
        self.logcat_refresh_btn = QPushButton(i18n.tr("logcat_refresh"))
        self.logcat_refresh_btn.clicked.connect(self.refresh_logcat)
        row.addWidget(self.logcat_refresh_btn)
        clear_btn = QPushButton(i18n.tr("logcat_clear"))
        clear_btn.clicked.connect(self.clear_logcat)
        row.addWidget(clear_btn)
        save_btn = QPushButton(i18n.tr("logcat_save"))
        save_btn.clicked.connect(self.save_logcat)
        row.addWidget(save_btn)
        row.addStretch(1)
        layout.addLayout(row)

        self.logcat_output = QPlainTextEdit()
        self.logcat_output.setReadOnly(True)
        layout.addWidget(self.logcat_output, 1)
        return page

    def refresh_logcat(self):
        self.logcat_refresh_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_logcat(out, exc),
                  adb_actions.logcat_dump, self.ip,
                  self.logcat_count.value(), self.logcat_level.currentData())

    def _on_logcat(self, output, exc):
        self.logcat_refresh_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.logcat_output.setPlainText(output or "")

    def clear_logcat(self):
        self._busy()
        self._run(lambda _out, exc: self._on_logcat_clear(exc),
                  adb_actions.logcat_clear, self.ip)

    def _on_logcat_clear(self, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.logcat_output.setPlainText("")

    def save_logcat(self):
        text = self.logcat_output.toPlainText()
        if not text:
            return
        default = os.path.join(
            os.path.expanduser("~"), "droidscout_logcat_"
            + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".log")
        path, _ = QFileDialog.getSaveFileName(self, i18n.tr("logcat_save"),
                                              default, "Log (*.log *.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.status.setText(i18n.tr("logcat_saved", path=path))
        except OSError as exc:
            self.status.setText(i18n.tr("toolkit_error", error=str(exc)[:200]))
