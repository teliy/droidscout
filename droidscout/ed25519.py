"""Минимальный Ed25519 (curve25519, edwards25519) на чистом Python.

Нужен для SPAKE2 протокола сопряжения ADB («Отладка по Wi-Fi», Android 11+):
boringssl в adbd реализует SPAKE2 именно на edwards25519
(crypto/curve25519/spake25519.c). Реализовано ровно то, что нужно
протоколу: декомпрессия точки, сложение/вычитание, скалярное
умножение (в том числе на базовую точку), кодирование точки
и приведение скаляра по модулю порядка подгруппы.

Формулы — стандартные расширенные координаты (X, Y, Z, T) твистед-кривой
Эдвардса a=-1, d=-121665/121666 (RFC 8032, complete addition formulas).
Корректность сверена тестами с cryptography (Ed25519PublicKey).
"""

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # порядок подгруппы

_D = (-121665 * pow(121666, P - 2, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

# Базовая точка Ed25519 (y = 4/5, x восстанавливается)
_BY = (4 * pow(5, P - 2, P)) % P


def _recover_x(y: int, sign: int) -> "int | None":
    """Восстановить x по y и биту знака. None — точки не существует."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
_BASE = (_BX, _BY, 1, _BX * _BY % P)          # расширенные координаты
_IDENT = (0, 1, 1, 0)                          # нейтральный элемент


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def decompress(data: bytes) -> "tuple | None":
    """32 байта -> (X, Y, Z, T) или None, если точка не на кривой."""
    if len(data) != 32:
        return None
    val = int.from_bytes(data, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    if y >= P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def encode(point: tuple) -> bytes:
    """(X, Y, Z, T) -> 32 байта (y | знак x, little-endian)."""
    x, y, z, _t = point
    zi = _inv(z)
    x = x * zi % P
    y = y * zi % P
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def add(p1: tuple, p2: tuple) -> tuple:
    """Сложение в расширенных координатах (полная формула, годится
    и для удвоения)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * _D % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def neg(p: tuple) -> tuple:
    x, y, z, t = p
    return (-x % P, y, z, -t % P)


def sub(p1: tuple, p2: tuple) -> tuple:
    return add(p1, neg(p2))


def mul(scalar: int, point: tuple) -> tuple:
    """Скалярное умножение double-and-add (скаляр < 2^255)."""
    scalar &= (1 << 256) - 1
    result = _IDENT
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        scalar >>= 1
    return result


def mul_base(scalar: int) -> tuple:
    return mul(scalar, _BASE)


def sc_reduce(data64: bytes) -> int:
    """Приведение 64-байтного little-endian скаляра по модулю L
    (эквивалент x25519_sc_reduce из boringssl)."""
    return int.from_bytes(data64, "little") % L
