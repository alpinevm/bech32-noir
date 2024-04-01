# random utils 
from scripts.ref_impl import bech32_decode, decode
def to_ascii_array(s: str):
    return [ord(c) for c in s]

def from_array_to_hex(arr: list[int]):
    return [bytes([a]).hex() for a in arr]

def ref_out():
    STRING = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
    print("bech32 ref", bech32_decode(STRING))
    print("address decode", decode(STRING[0:2].lower(), STRING))

def ta():
    STRING = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"
    print(to_ascii_array(STRING))

def fa():
    STORAGE_DUMP = [0, 8, 14, 11, 11, 20, 26, 29, 30, 25, 3, 22, 2, 11, 1, 23, 25, 11, 1, 7, 4, 15, 15, 19, 23, 18, 29, 20, 2, 3, 16, 24, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    LEN = 33
    print("u8 vals:", STORAGE_DUMP[0:LEN])
    print("hex:", from_array_to_hex(STORAGE_DUMP[0:LEN]))


if __name__ == "__main__":
    ref_out() 
