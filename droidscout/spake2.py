"""SPAKE2 (boringssl, curve25519) — ядро протокола сопряжения ADB.

Прямая портировка crypto/curve25519/spake25519.c из BoringSSL: именно
эту реализацию использует adbd при сопряжении «Отладка по Wi-Fi»
(Android 11+, adb/pairing_auth/pairing_auth.cpp).

Особенности протокола, воспроизведённые один в один:
* роль alice = клиент adb, bob = устройство;
* приватный скаляр: SHA512-хеш не нужен — 64 случайных байта,
  приведённые mod L и умноженные на 8 (левый сдвиг на 3 бита);
* скаляр пароля: SHA512(password) mod L, доведённый до кратности 8
  добавлением порядка подгруппы (L, 2L, 4L по младшим битам) — в
  boringssl это «password_scalar_hack», компенсирующий баг с
  пропущенным умножением на 8;
* маска: alice умножает парольный скаляр на точку M при генерации
  и на N при обработке ответа, bob — наоборот;
* ключ: SHA512 от транскрипта «с префиксами длины» (8 байт little-endian
  длины перед каждым полем): имена сторон, оба сообщения, общий
  Диффи-Хеллман, полный (не редуцированный!) SHA512-хеш пароля;
* имена в adb: b"adb pair client\\0" / b"adb pair server\\0" (с NUL,
  как sizeof строкового литерала в C).
"""

import hashlib
import secrets

from . import ed25519

ROLE_ALICE = "alice"   # клиент adb
ROLE_BOB = "bob"       # устройство

MSG_SIZE = 32          # SPAKE2_MAX_MSG_SIZE
KEY_SIZE = 64          # SPAKE2_MAX_KEY_SIZE

# Точки M и N (кодировка ed25519), из spake25519.c
_M = bytes.fromhex("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e")
_N = bytes.fromhex("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778")


def _mask_point(role: str, generate: bool) -> tuple:
    """Точка-маска: при генерации alice берёт M, bob — N;
    при обработке ответа наоборот (сверьтесь с spake25519.c)."""
    data = _M if (role == ROLE_ALICE) == generate else _N
    point = ed25519.decompress(data)
    if point is None:  # pragma: no cover - константа заведомо валидна
        raise ValueError("встроенная точка SPAKE2 не декодируется")
    return point


def _password_scalar(password: bytes) -> int:
    """SHA512(password) mod L, доведённый до кратности 8 добавлением L,
    2L, 4L по битам 0..2 (password_scalar_hack из spake25519.c)."""
    digest = hashlib.sha512(password).digest()
    scalar = ed25519.sc_reduce(digest)
    if scalar & 1:
        scalar += ed25519.L
    if scalar & 2:
        scalar += 2 * ed25519.L
    if scalar & 4:
        scalar += 4 * ed25519.L
    return scalar


def _update_with_length_prefix(sha, data: bytes) -> None:
    """SHA512_Update(len_le_8bytes || data) — как в boringssl."""
    sha.update(len(data).to_bytes(8, "little"))
    sha.update(data)


class Spake2:
    """Одна сторона обмена SPAKE2. Пример::

        alice = Spake2(ROLE_ALICE, b"adb pair client\\0", b"adb pair server\\0")
        msg = alice.generate_message(b"123456" + tls_exported)
        key = alice.process_message(their_msg)   # 64 байта
    """

    def __init__(self, role: str, my_name: bytes, their_name: bytes):
        if role not in (ROLE_ALICE, ROLE_BOB):
            raise ValueError("роль: ROLE_ALICE или ROLE_BOB")
        self.role = role
        self.my_name = bytes(my_name)
        self.their_name = bytes(their_name)
        self._my_msg = b""
        self._password_hash = b""
        self._password_scalar = 0
        self._private = 0
        self._done = False

    def generate_message(self, password: bytes) -> bytes:
        """Первое сообщение (32 байта) из общего секрета-пароля."""
        if self._my_msg:
            raise ValueError("сообщение уже сгенерировано")
        # Приватный скаляр: 64 случайных байта mod L, затем *8 (левый
        # сдвиг на 3 байта-бита в little-endian представлении).
        private = ed25519.sc_reduce(secrets.token_bytes(64)) * 8
        self._private = private

        # P = private * G
        p = ed25519.mul_base(private)

        # Полный хеш пароля идёт в транскрипт без редукции
        self._password_hash = hashlib.sha512(password).digest()
        self._password_scalar = _password_scalar(password)

        # P* = P + password_scalar * (M | N)
        mask = ed25519.mul(self._password_scalar, _mask_point(self.role, True))
        p_star = ed25519.add(p, mask)

        self._my_msg = ed25519.encode(p_star)
        return self._my_msg

    def process_message(self, their_msg: bytes) -> bytes:
        """Обработка ответа (32 байта) -> общий ключ (64 байта)."""
        if not self._my_msg:
            raise ValueError("сначала generate_message()")
        if self._done:
            raise ValueError("сообщение уже обработано")
        if len(their_msg) != MSG_SIZE:
            raise ValueError("сообщение партнёра должно быть 32 байта")
        q_star = ed25519.decompress(their_msg)
        if q_star is None:
            raise ValueError("точка партнёра не на кривой")
        self._done = True

        # Снимаем маску партнёра: Q = Q* - password_scalar * (N | M)
        peers_mask = ed25519.mul(self._password_scalar,
                                 _mask_point(self.role, False))
        q = ed25519.sub(q_star, peers_mask)

        # dh = private * Q
        dh = ed25519.encode(ed25519.mul(self._private, q))

        sha = hashlib.sha512()
        if self.role == ROLE_ALICE:
            for chunk in (self.my_name, self.their_name, self._my_msg,
                          their_msg):
                _update_with_length_prefix(sha, chunk)
        else:
            for chunk in (self.their_name, self.my_name, their_msg,
                          self._my_msg):
                _update_with_length_prefix(sha, chunk)
        _update_with_length_prefix(sha, dh)
        _update_with_length_prefix(sha, self._password_hash)
        return sha.digest()
