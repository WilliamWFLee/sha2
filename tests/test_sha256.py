"""
Tests for SHA256 only
"""

import pytest

from sha2 import SHA256


@pytest.fixture
def hasher():
    return SHA256()


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
