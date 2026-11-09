"""Модель таблицы устройств для QTableView."""

from typing import List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from .. import favorites, i18n, sortutil
from ..fingerprint import Device, type_label, verdict_label

COLUMNS = ("ip", "mac", "vendor", "hostname", "device_type", "model",
           "manufacturer", "confidence", "ports", "services", "status")

COLUMN_KEYS = ("col_ip", "col_mac", "col_vendor", "col_hostname", "col_type",
               "col_model", "col_manufacturer", "col_confidence", "col_ports",
               "col_services", "col_status")

NEW_COLOR = QColor(46, 204, 113, 36)
ANDROID_COLOR = QColor(46, 204, 113)
LIKELY_COLOR = QColor(241, 196, 15)
NO_COLOR = QColor(149, 165, 166)
MUTED_COLOR = QColor(122, 130, 136)   # строки-пустышки «только ping»


class DeviceModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices: List[Device] = []
        self.favorites = set()               # ключи (MAC/IP) избранных

    # Структура --------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.devices)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        try:
            orientation = Qt.Orientation(orientation)
        except (ValueError, TypeError):
            return None
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return i18n.tr(COLUMN_KEYS[section])
        return None

    # Данные -----------------------------------------------------------------
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        device = self.devices[index.row()]
        column = COLUMNS[index.column()]

        if role == Qt.DisplayRole:
            if column == "ip":
                starred = "★ " if favorites.device_hit(self.favorites, device) else ""
                return starred + device.ip
            if column == "mac":
                return device.mac or "—"
            if column == "vendor":
                return device.vendor or "—"
            if column == "hostname":
                return device.hostname or "—"
            if column == "device_type":
                return type_label(device.device_type)
            if column == "model":
                return device.model or "—"
            if column == "manufacturer":
                return device.manufacturer or device.vendor or "—"
            if column == "confidence":
                return f"{device.confidence}%"
            if column == "ports":
                return ", ".join(str(p) for p in sorted(device.ports)) or "—"
            if column == "services":
                return ", ".join(sorted(device.services)) or "—"
            if column == "status":
                return i18n.tr("status_new") if device.is_new else ""
            return ""
        if role == Qt.ForegroundRole:
            if device.ping_only:
                # хост виден только по ping — гасим всю строку серым
                return MUTED_COLOR
            if column == "confidence":
                if device.verdict == "android":
                    return ANDROID_COLOR
                if device.verdict == "likely":
                    return LIKELY_COLOR
                return NO_COLOR
        if role == Qt.BackgroundRole and device.is_new and not device.ping_only:
            return NEW_COLOR
        if role == Qt.FontRole and column in ("ip", "mac"):
            font = QFont()
            font.setStyleHint(QFont.Monospace)
            return font
        if role == Qt.TextAlignmentRole and column == "confidence":
            return int(Qt.AlignCenter)
        if role == Qt.ToolTipRole:
            return self._tooltip(device)
        return None

    @staticmethod
    def _tooltip(device: Device) -> str:
        lines = [
            f"IP: {device.ip}",
            f"MAC: {device.mac or '—'}",
            f"{i18n.tr('det_type')}: {type_label(device.device_type)}",
            f"{i18n.tr('det_android')}: {verdict_label(device.verdict)} ({device.confidence}%)",
        ]
        if device.model:
            lines.append(f"{i18n.tr('det_model')}: {device.model}")
        if device.ttl:
            lines.append(f"TTL: {device.ttl}")
        if device.ssdp_info:
            lines.append(f"UPnP: {device.ssdp_info}")
        if device.evidence:
            lines.append("")
            lines.append(i18n.tr("det_evidence") + ":")
            lines.extend("  • " + ev for ev in device.evidence[:8])
        if device.ping_only:
            lines.append("")
            lines.append(i18n.tr("tooltip_ping_only"))
        return "\n".join(lines)

    # Мутации ------------------------------------------------------------------
    def set_devices(self, devices: List[Device]) -> None:
        self.beginResetModel()
        self.devices = list(devices)
        self.endResetModel()

    def set_favorites(self, favs) -> None:
        """Новый набор избранного -> перерисовать колонку IP (звёздочки)."""
        self.favorites = set(favs or ())
        if self.devices:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self.devices) - 1, 0))

    def sort(self, column, order):
        """Сортировка по клику на заголовок.

        Без этого метода QAbstractTableModel рисует стрелки в заголовке,
        но не переставляет строки (дефолтный sort() пустой) — тот самый
        баг «стрелочки переключаются, а порядок не меняется». Числа
        (уверенность, порты) — по значению, IP — по октетам, текст —
        естественным порядком.
        """
        if not 0 <= column < len(COLUMNS) or len(self.devices) < 2:
            return
        self.layoutAboutToBeChanged.emit()
        reverse = Qt.SortOrder(order) == Qt.DescendingOrder
        key_func = self._sort_key(COLUMNS[column])
        order_rows = sorted(range(len(self.devices)),
                            key=lambda row: key_func(self.devices[row]),
                            reverse=reverse)
        if order_rows != list(range(len(self.devices))):
            for persistent in self.persistentIndexList():
                if persistent.isValid():
                    self.changePersistentIndex(
                        persistent,
                        self.index(order_rows.index(persistent.row()),
                                   persistent.column()))
            self.devices = [self.devices[row] for row in order_rows]
        self.layoutChanged.emit()

    @staticmethod
    def _sort_key(field: str):
        """Ключ строки для колонки: числа — числами, IP — по октетам."""
        if field == "ip":
            return lambda d: sortutil.ip_key(d.ip)
        if field == "confidence":
            return lambda d: (d.confidence,)
        if field == "ports":
            return lambda d: tuple(sorted(d.ports))
        if field == "status":
            return lambda d: (1 if d.is_new else 0,)
        if field == "device_type":
            return lambda d: sortutil.natural_key(type_label(d.device_type))
        if field == "mac":
            return lambda d: sortutil.natural_key(d.mac or "")
        if field == "services":
            return lambda d: sortutil.natural_key(", ".join(sorted(d.services)))
        if field == "vendor":
            return lambda d: sortutil.natural_key(d.vendor or "")
        if field == "model":
            return lambda d: sortutil.natural_key(d.model or "")
        return lambda d: sortutil.natural_key(d.manufacturer or d.vendor or "")

    def add_device(self, device: Device) -> None:
        for row, existing in enumerate(self.devices):
            if existing.ip == device.ip:
                self.devices[row] = device
                self.dataChanged.emit(self.index(row, 0), self.index(row, len(COLUMNS) - 1))
                return
        row = len(self.devices)
        self.beginInsertRows(QModelIndex(), row, row)
        self.devices.append(device)
        self.endInsertRows()

    def refresh_headers(self) -> None:
        self.headerDataChanged.emit(Qt.Horizontal, 0, len(COLUMNS) - 1)
        self.dataChanged.emit(self.index(0, 0),
                              self.index(max(0, len(self.devices) - 1), len(COLUMNS) - 1))

    def device_at(self, row: int):
        return self.devices[row] if 0 <= row < len(self.devices) else None
