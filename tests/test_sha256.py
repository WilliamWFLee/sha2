import pytest

from sha2 import SHA256


@pytest.fixture
def hasher():
    return SHA256()


def test_bit_not():
    assert SHA256._bit_not(0b10010010) == 0b11111111111111111111111101101101
    assert SHA256._bit_not(SHA256._bit_not(0b10010010)) == 0b10010010
    assert (
        SHA256._bit_not(0b10101001010100100100101001010110)
        == 0b01010110101011011011010110101001
    )


def test_r_rotate():
    assert SHA256._r_rotate(0b10010000, 4) == 0b1001
    assert SHA256._r_rotate(0b10100101, 2) == 0b01000000000000000000000000101001
    assert SHA256._r_rotate(0b1000, 4) == 2 ** 31


def test_ch():
    assert SHA256._ch(0b101010, 0b100100, 0b101110) == 0b100100
    assert SHA256._ch(0b111111, 0b101010, 0b101011) == 0b101010
    assert SHA256._ch(0b000000, 0b100101, 0b111010) == 0b111010


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


def test_empty_hash(hasher):
    assert (
        hasher.hexdigest()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_non_empty_hash(hasher):
    hasher.update(b"abc")
    assert (
        hasher.hexdigest()
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_longer_hash(hasher):
    hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    assert (
        hasher.hexdigest()
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )


def test_split_content(hasher):
    hasher.update(b"abcdbcdecdefdefg")
    hasher.update(b"efghfghighijhijkijkljklmklm")
    hasher.update(b"nlmnomnopnopq")

    assert (
        hasher.hexdigest()
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )
