"""Элементы QTreeWidget/QTableWidget с человеческой сортировкой.

Стандартные QTreeWidgetItem/QTableWidgetItem сравнивают текст
лексикографически: «10» < «9», порт 443 < 80, версия 10.2 < 9.1.
Эти классы сравнивают через sortutil.natural_key, а если у обеих
ячеек есть числовые данные в Qt.UserRole (порты, байты) — числами.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidgetItem, QTreeWidgetItem

from ..sortutil import natural_key


def _numeric_pair(a, b) -> bool:
    """Оба значения — числа (bool не считаем), можно сравнить напрямую."""
    return (isinstance(a, (int, float)) and not isinstance(a, bool)
            and isinstance(b, (int, float)) and not isinstance(b, bool))


class NaturalTreeItem(QTreeWidgetItem):
    """Строка дерева, сортирующаяся по-человечески."""

    def __lt__(self, other):
        tree = self.treeWidget()
        column = tree.sortColumn() if tree else 0
        mine = self.data(column, Qt.UserRole)
        theirs = other.data(column, Qt.UserRole)
        if _numeric_pair(mine, theirs):
            return mine < theirs
        return (natural_key(self.text(column))
                < natural_key(other.text(column)))


class NaturalTableItem(QTableWidgetItem):
    """Ячейка таблицы, сортирующаяся по-человечески."""

    def __lt__(self, other):
        mine = self.data(Qt.UserRole)
        theirs = other.data(Qt.UserRole)
        if _numeric_pair(mine, theirs):
            return mine < theirs
        return natural_key(self.text()) < natural_key(other.text())
