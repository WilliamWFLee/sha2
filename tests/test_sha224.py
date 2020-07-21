"""
Tests for SHA224 only
"""

import pytest

from sha2 import SHA224


@pytest.fixture
def hasher():
    return SHA224()


def test_empty_hash(hasher):
    assert (
        hasher.hexdigest() == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    )


def test_non_empty_hash(hasher):
    hasher.update(b"abc")
    assert (
        hasher.hexdigest() == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    )


def test_longer_hash(hasher):
    hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    assert (
        hasher.hexdigest() == "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    )


def test_split_content(hasher):
    hasher.update(b"abcdbcdecdefdefg")
    hasher.update(b"efghfghighijhijkijkljklmklm")
    hasher.update(b"nlmnomnopnopq")

    assert (
        hasher.hexdigest() == "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    )
