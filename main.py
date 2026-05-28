from utils.data_converters import hex_to_lsb_bits,lsb_bits_to_hex
if __name__ == "__main__":
    test_hex="0001"
    bits=hex_to_lsb_bits(test_hex)
    print(f"Hex: {test_hex} -> Bits: {bits}")
    reconstructed_hex=lsb_bits_to_hex(bits)
    print(f"Bits: {bits} -> Reconstructed Hex: {reconstructed_hex}")