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


def test_empty_hash(hasher):
    assert (
        hasher.hexdigest()
        == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )


def test_non_empty_hash(hasher):
    hasher.update(b"abc")
    assert (
        hasher.hexdigest()
        == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )


def test_longer_hash(hasher):
    hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    assert (
        hasher.hexdigest()
        == "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    )


def test_split_content(hasher):
    hasher.update(b"abcdbcdecdefdefg")
    hasher.update(b"efghfghighijhijkijkljklmklm")
    hasher.update(b"nlmnomnopnopq")

    assert (
        hasher.hexdigest()
        == "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    )
