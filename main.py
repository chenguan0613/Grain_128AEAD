from utils.data_converters import hex_to_lsb_bits,lsb_bits_to_hex,string_to_lsb_bits,lsb_bits_to_string
from crypto_engine.grain_v2 import Grain128AEADv2
from key_management.wrapper import KeyManager
import json
if __name__ == "__main__":
    manager=KeyManager()
    generated_key_hex=manager.generate_random_key_hex()
    print("Generated Key (Hex):", generated_key_hex)
    password="my_secure_password"
    ad_data="student_id:12345"
    #Locking the key
    key_dict=manager.wrap_key(password,generated_key_hex,ad_data,ad_is_hex=False)
    print("\nWrapped Key Data (JSON):\n", json.dumps(key_dict, indent=4))
    print("The ciphertext is:", key_dict["ciphertext"])
    #Normal unlocking the key
    try:
        recovered_key_hex=manager.unwrap_key(password,key_dict,ad_data,ad_is_hex=False)
        print("Recovered Key (Hex) successfully:", recovered_key_hex)
    except Exception as e:
        print("Failed to unwrap key:", str(e))
    
    #Attacking with wrong authentication data
    wrong_ad_data="student_id:54321"
    print("\nAttempting to unwrap with wrong AD: wrong_ad_data=", wrong_ad_data)
    try:
        recovered_key_hex=manager.unwrap_key(password,key_dict,wrong_ad_data,ad_is_hex=False)
    except Exception as e:
        print("Successfully stopped attack with wrong AD:\n", str(e))