import json
import os
class FileHandler:
    #(.key)
    @staticmethod
    def save_key_file(key_data_dict,file_path="data/secret.key"):
        file=open(file_path,"w",encoding="utf-8")
        json.dump(key_data_dict,file,indent=4)
        file.close()
        return file_path
    @staticmethod
    def load_key_file(file_path="data/secret.key"):
        file=open(file_path,"r",encoding="utf-8")
        key_data_dict=json.load(file)
        file.close()
        return key_data_dict
    @staticmethod
    def save_encrypted_file(iv_hex,ciphertext_hex,file_path="data/message.enc"):
        iv_clean=iv_hex.replace("0x","")
        ciphertext_clean=ciphertext_hex.replace("0x","")
        prepended_data=iv_clean+ciphertext_clean
        file=open(file_path,"w",encoding="utf-8")
        file.write(prepended_data)
        file.close()
        return file_path
    @staticmethod
    def load_encrypted_file(file_path="data/message.enc"):
        file=open(file_path,"r",encoding="utf-8")
        prepended_data=file.read().strip()
        file.close()
        iv_hex=prepended_data[:24]
        ciphertext_hex=prepended_data[24:]
        return iv_hex,ciphertext_hex
    @staticmethod
    def save_decrypted_file(plaintext,file_path="data/recovered.dec"):
        file=open(file_path,"w",encoding="utf-8")
        file.write(plaintext)
        file.close()
        return file_path