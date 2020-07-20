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
