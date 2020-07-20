#!/usr/bin/env python3
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

import argparse
import io
import os
import sys
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Tuple, Union


class SHA2Meta(ABCMeta):
    """
    Meta class for SHA2 hash objects
    """

    def __init__(self, name, bases, dct):
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
    # Digest length, as the number of words used from the hash values.
    # Defaults to None to use all of them
    DIGEST_LENGTH: Optional[int] = None
    # Constant words used in the compression function, a tuple of word-sized integers
    # Derived from various prime numbers
    K: tuple
    # The initial hash value, as a tuple of word-sized integers
    H: tuple

    _CHUNK_SIZE = 8 * 1024 ** 2

    def __init__(self, message: Optional[bytes] = None):
        """Creates a new SHA256 hash object

        :param message: The initial message to add to the hash, defaults to None
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
        return (x & y) | (cls._bit_not(x) & z)

    @staticmethod
    def _maj(x, y, z):
        """A majority function.

        For each binary digit, it is `1` if a majority of `x`, `y` or `z`
        have `1` in the corresponding place, otherwise it is `0`.
        """
        return (x & y) | (x & z) | (y & z)

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
    def _expand_message_block(cls, w):
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

    def _process_last_block(self) -> List[List[int]]:
        """
        Pads the final part of the message, and processes it into blocks
        """
        m = self._last_block
        k = ((self.BLOCK_SIZE - self.WORD_SIZE * 2 - len(m)) * 8 - 1) % (
            self.BLOCK_SIZE * 8
        )
        zeroes = (1 << k).to_bytes((k + 1) // 8, "big")
        length = self._message_length.to_bytes(self.WORD_SIZE * 2, "big")
        m = m + zeroes + length

        blocks, _ = self._process(m)
        return blocks

    def _compress(self, blocks: List[List[int]]):
        for block in blocks:
            a, b, c, d, e, f, g, h = self._hash
            self._expand_message_block(block)
            for w, k in zip(block, self.K):
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

    def update(self, message: Union[io.BufferedReader, bytes]):
        if isinstance(message, bytes):
            message = io.BytesIO(message)
        reading = True
        while reading:
            chunk = message.read(self._CHUNK_SIZE)
            if not chunk:
                break
            blocks, self._last_block = self._process(self._last_block + chunk)
            self._compress(blocks)
            self._message_length += len(chunk) * 8

    def digest(self):
        last_hash = self._hash[:]
        self._compress(self._process_last_block())
        digest = b"".join(
            h.to_bytes(self.WORD_SIZE, "big") for h in self._hash[: self.DIGEST_LENGTH]
        )
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
    # These are the first 32 bits of the fractional parts
    # of the square roots of the first eight prime numbers
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


class SHA224(SHA256):
    H = (
        0xC1059ED8,
        0x367CD507,
        0x3070DD17,
        0xF70E5939,
        0xFFC00B31,
        0x68581511,
        0x64F98FA7,
        0xBEFA4FA4,
    )

    DIGEST_LENGTH = 7


class SHA512(SHA2):
    """
    Class for SHA512 hash objects
    """

    WORD_SIZE = 8
    BLOCK_SIZE = 128

    # These are the first 64 bits of the fractional part of the cube root
    # of the first 80 prime numbers
    K = (
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    )
    # These are the first 64 bits of the fractional parts
    # of the square roots of the first eight prime numbers
    H = (
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )

    @classmethod
    def _usigma_0(cls, x):
        return cls._r_rotate(x, 28) ^ cls._r_rotate(x, 34) ^ cls._r_rotate(x, 39)

    @classmethod
    def _usigma_1(cls, x):
        return cls._r_rotate(x, 14) ^ cls._r_rotate(x, 18) ^ cls._r_rotate(x, 41)

    @classmethod
    def _sigma_0(cls, x):
        return cls._r_rotate(x, 1) ^ cls._r_rotate(x, 8) ^ (x >> 7)

    @classmethod
    def _sigma_1(cls, x):
        return cls._r_rotate(x, 19) ^ cls._r_rotate(x, 61) ^ (x >> 6)


class SHA384(SHA512):
    H = (
        0xCBBB9D5DC1059ED8,
        0x629A292A367CD507,
        0x9159015A3070DD17,
        0x152FECD8F70E5939,
        0x67332667FFC00B31,
        0x8EB44A8768581511,
        0xDB0C2E0D64F98FA7,
        0x47B5481DBEFA4FA4,
    )

    DIGEST_LENGTH = 6


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="sha2",
        description="SHA-2 family of secure hash algorithms written in Python",
    )

    parser.add_argument("filename", default=None, nargs="?")
    args = parser.parse_args()

    if args.filename is None:
        file = sys.stdin.buffer.raw
    else:
        if not os.path.exists(args.filename):
            parser.error(f"{args.filename} does not exist")
        file = open(args.filename, "rb")

    hasher = SHA256(file)
    print(hasher.hexdigest(), "-" if args.filename is None else args.filename)
