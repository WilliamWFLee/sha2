import pytest

from sha256 import SHA256


@pytest.fixture
def hasher():
    return SHA256()


def test_bit_not():
    assert SHA256.bit_not(0b10010010) == 0b11111111111111111111111101101101
    assert SHA256.bit_not(SHA256.bit_not(0b10010010)) == 0b10010010
    assert (
        SHA256.bit_not(0b10101001010100100100101001010110)
        == 0b01010110101011011011010110101001
    )


def test_r_rotate():
    assert SHA256.r_rotate(0b10010000, 4) == 0b1001
    assert SHA256.r_rotate(0b10100101, 2) == 0b01000000000000000000000000101001
    assert SHA256.r_rotate(0b1000, 4) == 2 ** 31


def test_ch():
    assert SHA256.ch(0b101010, 0b100100, 0b101110) == 0b100100
    assert SHA256.ch(0b111111, 0b101010, 0b101011) == 0b101010
    assert SHA256.ch(0b000000, 0b100101, 0b111010) == 0b111010


def test_maj():
    assert SHA256.maj(0b110011, 0b101010, 0b001010) == 0b101010
    assert SHA256.maj(0b101010, 0b010101, 0b000000) == 0b000000


def test_preprocess():
    assert SHA256._preprocess(b"") == [
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
    assert SHA256._preprocess(b"abc") == [
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


def test_hash(hasher):
    assert (
        hasher.to_hex(hasher.compute_hash(b""))
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    assert (
        hasher.to_hex(hasher.compute_hash(b"abc"))
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    assert (
        hasher.to_hex(
            hasher.compute_hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )
        )
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )

