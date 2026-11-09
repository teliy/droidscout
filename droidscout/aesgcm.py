"""AES-128-GCM на чистом Python (только стандартная библиотека).

Нужен для протокола сопряжения ADB (Android 11+, «Отладка по Wi-Fi»):
пакет PeerInfo шифруется AES-128-GCM ключом, выведенным из SPAKE2.
Полноценный AES-128 в чистом Python медленный, но сопряжение шифрует
один блок ~8 КБ — это доли секунды.

Реализованы: блочный шифр AES-128 (FIPS-197), режим CTR и GHASH
(NIST SP 800-38D). Совместимо с любой стандартной библиотекой —
проверено тестами против cryptography (NIST-векторы и случайные данные).
"""

# ---------------------------------------------------------------- таблицы AES
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    """Умножение на x в GF(2^8) (полином 0x11B)."""
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _key_expansion(key: bytes):
    """Раскрой ключа AES-128: 11 round-ключей по 4 слова."""
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        tmp = list(words[i - 1])
        if i % 4 == 0:
            tmp = tmp[1:] + tmp[:1]                      # RotWord
            tmp = [_SBOX[b] for b in tmp]                # SubWord
            tmp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ tmp[j] for j in range(4)])
    return [b"".join(bytes(w) for w in words[r * 4:r * 4 + 4])
            for r in range(11)]


def _add_round_key(state, rk: bytes):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= rk[c * 4 + r]


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        state[0][c] = a[0] ^ t ^ _xtime(a[0] ^ a[1])
        state[1][c] = a[1] ^ t ^ _xtime(a[1] ^ a[2])
        state[2][c] = a[2] ^ t ^ _xtime(a[2] ^ a[3])
        state[3][c] = a[3] ^ t ^ _xtime(a[3] ^ a[0])


def _encrypt_block(rks, block: bytes) -> bytes:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, rks[0])
    for rnd in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rks[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, rks[10])
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ---------------------------------------------------------------------- GHASH
def _gmul(x: int, y: int) -> int:
    """Умножение в GF(2^128) с полиномом GCM (R = 0xE1000...0)."""
    r = 0xE1000000000000000000000000000000
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def _ghash(h: bytes, aad: bytes, data: bytes) -> bytes:
    """GHASH_H(AAD || pad || CT || pad || len64(AAD) || len64(CT))."""
    hv = int.from_bytes(h, "big")

    def blocks(buf: bytes):
        for i in range(0, len(buf), 16):
            yield buf[i:i + 16].ljust(16, b"\x00")

    acc = 0
    for blk in list(blocks(aad)) + list(blocks(data)):
        acc = _gmul(acc ^ int.from_bytes(blk, "big"), hv)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(data) * 8).to_bytes(8, "big")
    acc = _gmul(acc ^ int.from_bytes(lens, "big"), hv)
    return acc.to_bytes(16, "big")


# --------------------------------------------------------------------- AESGCM
class AesGcm:
    """AES-128-GCM: encrypt возвращает ct||tag (как openssl/boringssl)."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128-GCM: ключ ровно 16 байт")
        self._rks = _key_expansion(key)

    def _keystream(self, j0: bytes, length: int):
        counter = int.from_bytes(j0[12:16], "big")
        base = j0[:12]
        while length > 0:
            inc = counter.to_bytes(4, "big")
            block = _encrypt_block(self._rks, base + inc)
            yield block
            length -= 16
            counter = (counter + 1) & 0xFFFFFFFF

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != 12:
            raise ValueError("nonce ровно 12 байт")
        j0 = nonce + b"\x00\x00\x00\x01"
        eky = _encrypt_block(self._rks, j0)            # E(K, J0) для тега
        out = bytearray()
        ks = self._keystream(nonce + b"\x00\x00\x00\x02", len(plaintext))
        for chunk, pad in zip(_chunks(plaintext, 16), ks):
            out.extend(b ^ p for b, p in zip(chunk, pad))
        tag_src = _ghash(_encrypt_block(self._rks, b"\x00" * 16), aad, bytes(out))
        tag = bytes(t ^ e for t, e in zip(tag_src, eky))
        return bytes(out) + tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("GCM: данные короче тега")
        ct, tag = ciphertext[:-16], ciphertext[-16:]
        j0 = nonce + b"\x00\x00\x00\x01"
        eky = _encrypt_block(self._rks, j0)
        tag_src = _ghash(_encrypt_block(self._rks, b"\x00" * 16), aad, ct)
        calc = bytes(t ^ e for t, e in zip(tag_src, eky))
        if calc != tag:
            raise ValueError("GCM: несовпадение аутентификационного тега")
        out = bytearray()
        ks = self._keystream(nonce + b"\x00\x00\x00\x02", len(ct))
        for chunk, pad in zip(_chunks(ct, 16), ks):
            out.extend(b ^ p for b, p in zip(chunk, pad))
        return bytes(out)


def _chunks(buf: bytes, size: int):
    for i in range(0, len(buf), size):
        yield buf[i:i + size]
