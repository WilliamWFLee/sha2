from sha2 import SHA2


def test_maj():
    assert SHA2._maj(0b110011, 0b101010, 0b001010) == 0b101010
    assert SHA2._maj(0b101010, 0b010101, 0b000000) == 0b000000
