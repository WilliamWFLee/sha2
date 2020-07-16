import math
from typing import List

# Constants in bits
WORD_SIZE = 32
BLOCK_SIZE = 512

# Constant words, K0 to K63
# These are the first 32 bits of the fractional part of the cube root
# of the first 64 prime numbers
K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def r_shift(x, n):
    return x >> n


def r_rotate(x, n):
    return (x >> n) | (x << (WORD_SIZE - n)) % 2 ** WORD_SIZE


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def usigma_0(x):
    return r_shift(x, 2) ^ r_shift(x, 13) ^ r_shift(x, 22)


def usigma_1(x):
    return r_shift(x, 6) ^ r_shift(x, 11) ^ r_shift(x, 25)


def sigma_0(x):
    return r_shift(x, 7) ^ r_shift(x, 18) ^ r_rotate(x, 3)


def sigma_1(x):
    return r_shift(x, 17) ^ r_shift(x, 19) ^ r_rotate(x, 10)


def preprocess(m: bytes) -> List[List[int]]:
    l = len(m)
    k = (447 - l * 8) % BLOCK_SIZE

    zeroes = (1 << k).to_bytes(math.ceil(k / 8), "big")
    length = (l * 8).to_bytes(8, "big")
    m = m + zeroes + length

    blocks = []

    for i in range(0, len(m), (BLOCK_SIZE // 8)):
        block = m[i : i + (BLOCK_SIZE // 8)]
        words = []
        for j in range(0, (BLOCK_SIZE // 8), (WORD_SIZE // 8)):
            words += [int.from_bytes(block[j : j + (WORD_SIZE // 8)], "big")]
        blocks += [words]

    return blocks


def calculate_message_schedule(words: List[int]) -> List[int]:
    w = words[:]
    for i in range(16, 64):
        w += [
            (sigma_1(w[i - 2]) + w[i - 7] + sigma_0(w[i - 15]) + w[i - 16])
            % 2 ** WORD_SIZE
        ]

    return w


def compute_hash(message: bytes = b"") -> bytes:
    # The initial hash value
    # These are the first 32 bits of the fractional parts
    # of the square roots of the first eight prime numbers
    H = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    # Processes the message into a list of blocks, each a list of words
    blocks = preprocess(message)
    for block in blocks:
        a, b, c, d, e, f, g, h = H
        msg_sched = calculate_message_schedule(block)
        for w, k in zip(msg_sched, K):
            t1 = h + usigma_1(e) + ch(e, f, g) + k + w
            t2 = usigma_0(a) + maj(a, b, c)
            a, b, c, d, e, f, g, h = (t1 + t2, a, b, c, d + t1, e, f, g)

        H = [
            (reg + word) % (2 ** WORD_SIZE) for reg, word in zip((a, b, c, d, e, f, g, h), H)
        ]

    return b"".join(h.to_bytes(WORD_SIZE // 8, "big") for h in H)


def to_hex(digest: bytes):
    return f"{int.from_bytes(digest, 'big'):x}"
