import math
from abc import ABC, abstractmethod
from typing import List


class SHA2(ABC):
    """
    Base class for SHA-2 hash objects
    """

    # The number of bits used in calculations
    WORD_SIZE: int
    # The size of blocks in bits for each loop of the compression function
    BLOCK_SIZE: int
    # The size of the block appended to the message, indicating the length of the message
    LENGTH_BLOCK_SIZE: int
    # Constant words used in the compression function, a tuple of word-sized integers
    # Derived from various prime numbers
    K: tuple
    # The initial hash value, as a tuple of word-sized integers
    H: tuple

    @staticmethod
    def to_hex(digest: bytes):
        return f"{int.from_bytes(digest, 'big'):x}"

    @classmethod
    def bit_not(cls, x):
        return (1 << cls.WORD_SIZE) - 1 - x

    @classmethod
    def r_rotate(cls, x, n):
        return ((x >> n) | x << (cls.WORD_SIZE - n)) % (2 ** cls.WORD_SIZE)

    @classmethod
    def ch(cls, x, y, z):
        return (x & y) ^ (cls.bit_not(x) & z)

    @staticmethod
    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    @abstractmethod
    def usigma_0(cls, x):
        pass

    @classmethod
    @abstractmethod
    def usigma_1(cls, x):
        pass

    @classmethod
    @abstractmethod
    def sigma_0(cls, x):
        pass

    @classmethod
    @abstractmethod
    def sigma_1(cls, x):
        pass

    @classmethod
    def _preprocess(cls, m: bytes) -> List[List[int]]:
        k = (cls.BLOCK_SIZE - cls.LENGTH_BLOCK_SIZE - 1 - len(m) * 8) % cls.BLOCK_SIZE

        zeroes = (1 << k).to_bytes(math.ceil(k / 8), "big")
        length = (len(m) * 8).to_bytes(8, "big")
        m = m + zeroes + length

        blocks = []

        for i in range(0, len(m), (cls.BLOCK_SIZE // 8)):
            block = m[i : i + (cls.BLOCK_SIZE // 8)]
            words = []
            for j in range(0, (cls.BLOCK_SIZE // 8), (cls.WORD_SIZE // 8)):
                words += [int.from_bytes(block[j : j + (cls.WORD_SIZE // 8)], "big")]
            blocks += [words]

        return blocks

    @classmethod
    def _expand_message_block(cls, words):
        w = words[:]
        for i in range(16, len(cls.K)):
            w += [
                (cls.sigma_1(w[i - 2]) + w[i - 7] + cls.sigma_0(w[i - 15]) + w[i - 16])
                % 2 ** cls.WORD_SIZE
            ]

        return w

    def compute_hash(self, message: bytes) -> bytes:
        H = list(self.H)
        blocks = self._preprocess(message)
        for block in blocks:
            a, b, c, d, e, f, g, h = H
            msg_sched = self._expand_message_block(block)
            for w, k in zip(msg_sched, self.K):
                t1 = h + self.usigma_1(e) + self.ch(e, f, g) + k + w
                t2 = self.usigma_0(a) + self.maj(a, b, c)

                h = g
                g = f
                f = e
                e = (d + t1) % (2 ** self.WORD_SIZE)
                d = c
                c = b
                b = a
                a = (t1 + t2) % (2 ** self.WORD_SIZE)

            H = [
                (reg + word) % (2 ** self.WORD_SIZE)
                for reg, word in zip((a, b, c, d, e, f, g, h), H)
            ]

        return b"".join(h.to_bytes(self.WORD_SIZE // 8, "big") for h in H)


class SHA256(SHA2):
    WORD_SIZE = 32
    BLOCK_SIZE = 512
    LENGTH_BLOCK_SIZE = 64
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
    # These are the fractional parts of the square roots of the first eight prime numbers
    H = (
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    )

    @classmethod
    def usigma_0(cls, x):
        return cls.r_rotate(x, 2) ^ cls.r_rotate(x, 13) ^ cls.r_rotate(x, 22)

    @classmethod
    def usigma_1(cls, x):
        return cls.r_rotate(x, 6) ^ cls.r_rotate(x, 11) ^ cls.r_rotate(x, 25)

    @classmethod
    def sigma_0(cls, x):
        return cls.r_rotate(x, 7) ^ cls.r_rotate(x, 18) ^ (x >> 3)

    @classmethod
    def sigma_1(cls, x):
        return cls.r_rotate(x, 17) ^ cls.r_rotate(x, 19) ^ (x >> 10)


if __name__ == "__main__":
    sha256 = SHA256()
    print(SHA2.to_hex(sha256.compute_hash(b"")))
