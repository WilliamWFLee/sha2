import sha256


def test_r_shift():
    assert sha256.r_shift(0b10010000, 4) == 0b1001
    assert sha256.r_shift(0b10100101, 2) == 0b101001
    assert sha256.r_shift(0b1000, 4) == 0


def test_r_rotate():
    assert sha256.r_rotate(0b10010000, 4) == 0b1001
    assert sha256.r_rotate(0b10100101, 2) == 0b01000000000000000000000000101001
    assert sha256.r_rotate(0b1000, 4) == 2 ** 31