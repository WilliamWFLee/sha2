import sha256


def test_r_rotate():
    assert sha256.r_rotate(0b10010000, 4) == 0b1001
    assert sha256.r_rotate(0b10100101, 2) == 0b01000000000000000000000000101001
    assert sha256.r_rotate(0b1000, 4) == 2 ** 31


def test_ch():
    assert sha256.ch(0b101010, 0b100100, 0b101110) == 0b100100
    assert sha256.ch(0b111111, 0b101010, 0b101011) == 0b101010
    assert sha256.ch(0b000000, 0b100101, 0b111010) == 0b111010


def test_maj():
    assert sha256.maj(0b110011, 0b101010, 0b001010) == 0b101010
    assert sha256.maj(0b101010, 0b010101, 0b000000) == 0b000000
