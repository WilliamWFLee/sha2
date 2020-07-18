"""
sha2 - Pure Python implementation of SHA-2 family of secure hash algorithms

MIT License

Copyright (c) 2020 William Lee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import math
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Tuple


class SHA2Meta(ABCMeta):
    def __init__(self, name, bases, dct):
        """
        Modulo used for addditon
        """
        super().__init__(name, bases, dct)
        if "WORD_SIZE" in dct:
            self._MODULO = 2 ** (self.WORD_SIZE * 8)


class SHA2(metaclass=SHA2Meta):
    """
    Base class for SHA-2 hash objects
    """

    # The number of bytes used in calculations
    WORD_SIZE: int
    # The size of blocks in bytes for each loop of the compression function
    BLOCK_SIZE: int
    # The size of the block appended to the message, indicating the length of the message
    LENGTH_BLOCK_SIZE: int
    # Constant words used in the compression function, a tuple of word-sized integers
    # Derived from various prime numbers
    K: tuple
    # The initial hash value, as a tuple of word-sized integers
    H: tuple

    def __init__(self, message: Optional[bytes] = None):
        """Creates a new SHA256 hash object

        :param message: The initial message to add to the hash - equivalent to calling `update()`-  defaults to None
        :type message: Optional[bytes], optional
        """
        # The current state of the hash algorithm
        self._hash = list(self.H)
        # The last block (complete or partial) to be added to the hash object
        self._last_block = b""
        # The length of the message in bits
        self._message_length = 0

        if message is not None:
            self.update(message)

    @property
    def message_length(self):
        """
        The message length being digested in bytes
        """
        return self._message_length

    @staticmethod
    def _to_hex(digest: bytes):
        return f"{int.from_bytes(digest, 'big'):x}"

    @classmethod
    def _bit_not(cls, x):
        """Implements a bitwise NOT operation on x 
        as if it were an unsigned integer of length `cls.WORD_SIZE`.
        """
        return (1 << cls.WORD_SIZE * 8) - 1 - x

    @classmethod
    def _r_rotate(cls, x, n):
        """
        Implements a right rotation of an integer `x` by `n` places,
        to give an integer of length `cls.WORD_SIZE`.
        """
        return ((x >> n) | x << (cls.WORD_SIZE * 8 - n)) % cls._MODULO

    # The six logical functions used in the SHA-256
    @classmethod
    def _ch(cls, x, y, z):
        """For each binary digit, the binary digit of `y`
        is chosen if the corresponding digit in `x` is `1`,
        otherwise the binary digit of `z` is chosen.
        """
        return (x & y) ^ (cls._bit_not(x) & z)

    @staticmethod
    def _maj(x, y, z):
        """A majority function.

        For each binary digit, it is `1` if a majority of `x`, `y` or `z`
        have `1` in the corresponding place, otherwise it is `0`.
        """
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    @abstractmethod
    def _usigma_0(cls, x):
        pass

    @classmethod
    @abstractmethod
    def _usigma_1(cls, x):
        pass

    @classmethod
    @abstractmethod
    def _sigma_0(cls, x):
        pass

    @classmethod
    @abstractmethod
    def _sigma_1(cls, x):
        pass

    @classmethod
    def _process(cls, m: bytes) -> Tuple[List[List[int]], bytes]:
        """Processes an arbitrary-length bytes object in a list of blocks,
        each block a list of words, with the words and blocks
        the appropriate size for the algorithm.
        """
        blocks = []

        for i in range(0, len(m) // cls.BLOCK_SIZE):
            block = m[i * cls.BLOCK_SIZE : (i + 1) * cls.BLOCK_SIZE]
            words = []
            for j in range(0, cls.BLOCK_SIZE, cls.WORD_SIZE):
                words += [int.from_bytes(block[j : j + cls.WORD_SIZE], "big")]
            blocks += [words]

        return blocks, m[len(m) // cls.BLOCK_SIZE * cls.BLOCK_SIZE :]

    @classmethod
    def _expand_message_block(cls, words):
        w = words[:]
        for i in range(16, len(cls.K)):
            w += [
                (
                    cls._sigma_1(w[i - 2])
                    + w[i - 7]
                    + cls._sigma_0(w[i - 15])
                    + w[i - 16]
                )
                % cls._MODULO
            ]

        return w

    def _process_last_block(self) -> List[List[int]]:
        """
        Pads the final part of the message, and processes it into blocks
        """
        m = self._last_block
        k = ((self.BLOCK_SIZE - self.LENGTH_BLOCK_SIZE - len(m)) * 8 - 1) % self._MODULO
        zeroes = (1 << k).to_bytes((k + 1) // 8, "big")
        length = self._message_length.to_bytes(self.LENGTH_BLOCK_SIZE, "big")
        m = m + zeroes + length

        blocks, _ = self._process(m)
        return blocks

    def _compress(self, blocks: List[List[int]]):
        for block in blocks:
            a, b, c, d, e, f, g, h = self._hash
            W = self._expand_message_block(block)
            for w, k in zip(W, self.K):
                t1 = h + self._usigma_1(e) + self._ch(e, f, g) + k + w
                t2 = self._usigma_0(a) + self._maj(a, b, c)

                h = g
                g = f
                f = e
                e = (d + t1) % self._MODULO
                d = c
                c = b
                b = a
                a = (t1 + t2) % self._MODULO

            self._hash = [
                (r + w) % self._MODULO
                for r, w in zip((a, b, c, d, e, f, g, h), self._hash)
            ]

    def update(self, message: bytes):
        blocks, self._last_block = self._process(self._last_block + message)
        self._compress(blocks)
        self._message_length += len(message) * 8

    def digest(self):
        last_hash = self._hash[:]
        self._compress(self._process_last_block())
        digest = b"".join(h.to_bytes(self.WORD_SIZE, "big") for h in self._hash)
        self._hash = last_hash

        return digest

    def hexdigest(self):
        return self._to_hex(self.digest())


class SHA256(SHA2):
    """
    Class for SHA256 hash objects
    """

    WORD_SIZE = 4
    BLOCK_SIZE = 64
    LENGTH_BLOCK_SIZE = 8
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
    def _usigma_0(cls, x):
        return cls._r_rotate(x, 2) ^ cls._r_rotate(x, 13) ^ cls._r_rotate(x, 22)

    @classmethod
    def _usigma_1(cls, x):
        return cls._r_rotate(x, 6) ^ cls._r_rotate(x, 11) ^ cls._r_rotate(x, 25)

    @classmethod
    def _sigma_0(cls, x):
        return cls._r_rotate(x, 7) ^ cls._r_rotate(x, 18) ^ (x >> 3)

    @classmethod
    def _sigma_1(cls, x):
        return cls._r_rotate(x, 17) ^ cls._r_rotate(x, 19) ^ (x >> 10)


if __name__ == "__main__":
    sha256 = SHA256()
    sha256.update(b"abc")
    print(sha256.hexdigest())
