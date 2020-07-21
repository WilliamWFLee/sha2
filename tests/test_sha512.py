"""
Tests for SHA512 only
"""

import pytest

from sha2 import SHA512


@pytest.fixture
def hasher():
    return SHA512()


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
