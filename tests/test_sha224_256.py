"""
Tests for SHA224 and SHA256

SHA224 is derived from SHA256, so this file tests the common functions
between them
"""

import pytest

from sha2 import SHA256


@pytest.fixture
def hasher():
    return SHA256()


def test_bit_not():
    assert SHA256._bit_not(0x92) == 0xFFFFFF6D
    assert SHA256._bit_not(SHA256._bit_not(0x92)) == 0x92
    assert SHA256._bit_not(0xA9524A56) == 0x56ADB5A9


def test_r_rotate():
    assert SHA256._r_rotate(0x90, 4) == 0x09
    assert SHA256._r_rotate(0xA5, 2) == 0x40000029
    assert SHA256._r_rotate(0x08, 4) == 2 ** 31


def test_ch():
    assert SHA256._ch(0x2A, 0x24, 0x2E) == 0x24
    assert SHA256._ch(0x3F, 0x2A, 0x2B) == 0x2A
    assert SHA256._ch(0x0, 0x25, 0x3A) == 0x3A


def test_process_last_block(hasher):
    assert hasher._process_last_block() == [
        [
            0x80000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        ]
    ]

    hasher.update(b"abc")
    assert hasher._process_last_block() == [
        [
            0x61626380,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000018,
        ]
    ]
