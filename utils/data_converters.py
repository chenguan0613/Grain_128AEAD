def hex_to_lsb_bits(hex_string):
    hex_string=hex_string.replace("0x","")
    byte_data=bytes.fromhex(hex_string)
    bit_list=[]
    for byte in byte_data:
        for i in range(8):
            bit_list.append(byte>>i & 1)
    return bit_list

def lsb_bits_to_hex(bit_list):
    hex_string="0x"
    for i in range(0,len(bit_list),8):
        byte=0
        for j in range(8):
            if i+j<len(bit_list):
                byte|=(bit_list[i+j] & 1)<<j
        hex_string+=format(byte,'02x')
    return hex_string