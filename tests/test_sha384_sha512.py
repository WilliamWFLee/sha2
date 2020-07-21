"""
Tests for the common functions of SHA384 and SHA512
"""

import pytest

from sha2 import SHA512


@pytest.fixture
def hasher():
    return SHA512()


def test_bit_not():
    assert SHA512._bit_not(0x92) == 0xFFFFFFFFFFFFFF6D
    assert SHA512._bit_not(SHA512._bit_not(0x92)) == 0x92
    assert SHA512._bit_not(0xA9524A56) == 0xFFFFFFFF56ADB5A9


def test_r_rotate():
    assert SHA512._r_rotate(0x90, 4) == 0x09
    assert SHA512._r_rotate(0xA5, 2) == 0x4000000000000029
    assert SHA512._r_rotate(0x08, 4) == 2 ** 63


def test_ch():
    assert SHA512._ch(0x2A, 0x24, 0x2E) == 0x24
    assert SHA512._ch(0x3F, 0x2A, 0x2B) == 0x2A
    assert SHA512._ch(0x0, 0x25, 0x3A) == 0x3A


def test_process_last_block(hasher):
    assert hasher._process_last_block() == [
        [
            0x8000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ]
    ]

    hasher.update(b"abc")
    assert hasher._process_last_block() == [
        [
            0x6162638000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000018,
        ]
    ]
