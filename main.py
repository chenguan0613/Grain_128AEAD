import sys
import os
import secrets
import traceback
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from ui_grain import Ui_MainWindow 

from crypto_engine.grain_v2 import Grain128AEADv2
from key_management.wrapper import KeyManager
from file_io.file_handler import FileHandler
from utils.data_converters import hex_to_lsb_bits, lsb_bits_to_hex, string_to_lsb_bits, lsb_bits_to_string

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class GrainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("Grain-128AEAD Cipher Console")
        self.setFixedSize(832, 655)
        
        self.key_manager = KeyManager()
        self.file_handler = FileHandler()

        self.load_stylesheet("style.qss")
        self.connect_signals()

    def load_stylesheet(self, filename):
        qss_path = resource_path(filename)
        try:
            with open(qss_path, "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            pass

    def connect_signals(self):
        #Key management block
        self.ui.btn_generate_key.clicked.connect(self.logic_generate_key)
        self.ui.btn_wrap_save.clicked.connect(self.logic_wrap_key)
        self.ui.btn_load_key.clicked.connect(self.logic_unwrap_key)
        self.ui.btn_generate_aes_nonce.clicked.connect(self.logic_generate_aes_nonce)
        self.ui.btn_generate_salt.clicked.connect(self.logic_generate_salt)

        #IV management block
        self.ui.btn_generate_iv.clicked.connect(self.logic_generate_iv)

        #Encryption&Decryption Block
        self.ui.btn_file_load.clicked.connect(self.logic_file_load)
        self.ui.btn_file_save.clicked.connect(self.logic_file_save_dir)
        self.ui.btn_file_encrypt.clicked.connect(self.logic_file_encrypt)
        self.ui.btn_file_decrypt.clicked.connect(self.logic_file_decrypt)
        self.ui.btn_manual_encrypt.clicked.connect(self.logic_manual_encrypt)
        self.ui.btn_manual_decrypt.clicked.connect(self.logic_manual_decrypt)

        #UI Interlock Mechanism
        self.ui.radioButton_4.toggled.connect(self.toggle_file_buttons)
        self.ui.radioButton_5.toggled.connect(self.toggle_file_buttons)
        self.ui.radio_manual_encypt.toggled.connect(self.toggle_manual_buttons)
        self.ui.radio_manual_decrypt.toggled.connect(self.toggle_manual_buttons)

        self.ui.radioButton_4.setChecked(True)
        self.ui.radio_manual_encypt.setChecked(True)
        self.toggle_file_buttons()
        self.toggle_manual_buttons()

    def toggle_file_buttons(self):
        is_encrypt = self.ui.radioButton_4.isChecked()
        self.ui.btn_file_encrypt.setEnabled(is_encrypt)
        self.ui.btn_file_decrypt.setEnabled(not is_encrypt)

    def toggle_manual_buttons(self):
        is_encrypt = self.ui.radio_manual_encypt.isChecked()
        self.ui.btn_manual_encrypt.setEnabled(is_encrypt)
        self.ui.btn_manual_decrypt.setEnabled(not is_encrypt)

    def show_error(self, title, exception_obj):
        error_details = traceback.format_exc()
        print(f"\n{'='*20} {title} {'='*20}")
        print(error_details)
        print("========================================================\n")
        
        error_msg = str(exception_obj).strip()
        if "non-hexadecimal" in error_msg:
            error_msg = "An invalid hexadecimal character was entered (please check for any mixed-in letters or extra spaces)!"
        elif not error_msg: 
            error_msg = repr(exception_obj) 
            
        QMessageBox.critical(self, title, f"Operation failed! Brief reason: {error_msg} ")

    def _prepare_engine(self):
        key_hex = self.ui.input_key.text().strip().replace("0x", "")
        iv_hex = self.ui.input_iv.text().strip().replace("0x", "")
        
        if len(key_hex) != 32:
            raise ValueError(f"Key length error! Must be 32-bit Hex characters (128-bit), currently {len(key_hex)} bits.")
        if len(iv_hex) != 24:
            raise ValueError(f"IV length error! Must be 24-bit Hex characters (96-bit), currently {len(iv_hex)} bits.")
            
        key_bits = hex_to_lsb_bits(key_hex)
        iv_bits = hex_to_lsb_bits(iv_hex)

        engine = Grain128AEADv2()
        
        engine.load_key_and_iv(key_bits, iv_bits)
        self.ui.state_nfsr_load.setText("0x" + lsb_bits_to_hex(engine.NFSR)[2:].zfill(32))
        self.ui.state_lfsr_load.setText("0x" + lsb_bits_to_hex(engine.LFSR)[2:].zfill(32))
        
        engine.initialise()
        self.ui.state_nfsr_init.setText("0x" + lsb_bits_to_hex(engine.NFSR)[2:].zfill(32))
        self.ui.state_lfsr_init.setText("0x" + lsb_bits_to_hex(engine.LFSR)[2:].zfill(32))
        
        return engine

    def logic_generate_key(self):
        self.ui.input_key.setText("0x"+self.key_manager.generate_random_key_hex())

    def logic_generate_aes_nonce(self):
        self.ui.input_aes_nonce.setText("0x"+secrets.token_hex(12))

    def logic_generate_salt(self):
        self.ui.input_salt.setText("0x"+secrets.token_hex(16))

    def logic_generate_iv(self):
        if self.ui.check_auto_iv.isChecked():
            self.ui.input_iv.setText("0x" + secrets.token_hex(12)) 
        else:
            QMessageBox.warning(self, "Operation rejected", "You must check 'Automatically Generate unique IV' before it can be generated automatically.")

    def logic_wrap_key(self):
        try:
            pwd = self.ui.input_password.text()
            key_hex = self.ui.input_key.text()
            ad = self.ui.input_ad.text().strip()
            
            salt_val=self.ui.input_salt.text().strip()
            iters_val=self.ui.input_iterations.text().strip()
            nonce_val=self.ui.input_aes_nonce.text().strip()

            if not pwd or not key_hex:
                raise ValueError("Password 和 Key cannot be empty")
            
            is_hex = (self.ui.combo_ad_mode.currentText() == "Hex")
            
            if is_hex and ad:
                try:
                    bytes.fromhex(ad.replace("0x", ""))
                except ValueError:
                    raise ValueError("AD format conflict: You selected Hex mode, but entered non-hexadecimal normal characters!")

            wrapped_data = self.key_manager.wrap_key(
                password_str=pwd, 
                grain_key_hex=key_hex, 
                ad_data=ad, 
                ad_is_hex=is_hex,
                custom_salt_hex=salt_val,
                custom_iterations=iters_val,
                custom_nonce_hex=nonce_val
            )
            
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Wrapped Key", "", "Key Files (*.key)")
            if save_path:
                if not save_path.endswith(".key"):
                    save_path +=".key"
                self.file_handler.save_key_file(wrapped_data, save_path)
                auto_generated = []
                if not salt_val: 
                    auto_generated.append(f"Salt (16-byte): 0x{wrapped_data['salt']}")
                if not iters_val: auto_generated.append(f"Iteration Count: {wrapped_data['iterations']} times")
                if not nonce_val: auto_generated.append(f"Nonce (AES-CCM): 0x{wrapped_data['nonce']}")
                if auto_generated:
                    items_str = "\n• ".join(auto_generated)
                    success_msg = (f"The key has been successfully wrapped and saved!\n\n"
                    f"\nSince you did not provide the following parameters, the system automatically generated a high-strength security value for you:\n"
                                f"• {items_str}\n\n"
                                f"You can open the .key file to view this final data generated by the system.")
                else:
                    success_msg = "The key has been wrapped and saved exactly according to the custom parameters you entered!"
                QMessageBox.information(self, "Success",success_msg)
        except Exception as e:
            self.show_error("Key Wrapping faild",e)

    def logic_unwrap_key(self):
        try:
            pwd = self.ui.input_password.text()
            ad = self.ui.input_ad.text().strip()
            
            if not pwd:
                raise ValueError("A password must be entered to decrypt the key file.")
                
            load_path, _ = QFileDialog.getOpenFileName(self, "Load Wrapped Key", "", "Key Files (*.key)")
            if load_path:
                is_hex = (self.ui.combo_ad_mode.currentText() == "Hex")
                key_data = self.file_handler.load_key_file(load_path)
                unwrapped_key_hex = self.key_manager.unwrap_key(pwd, key_data, ad, is_hex)
                
                self.ui.input_key.setText("0x" + unwrapped_key_hex)
                QMessageBox.information(self, "Success", "The key has been decrypted (unwrapped) from the file and loaded into the console.")
        except Exception as e:
            self.show_error("Key Unwrapping faild", e)

    def logic_manual_encrypt(self):
        try:
            input_text = self.ui.text_manual_input.toPlainText()
            if not input_text: raise ValueError("Please enter the plain ASCII text that you want to encrypt.")
            
            engine = self._prepare_engine()
            msg_bits = string_to_lsb_bits(input_text)
            cipher_bits = engine.encrypt(msg_bits)
            
            self.ui.text_manual_output.setText(lsb_bits_to_hex(cipher_bits))
        except Exception as e:
            self.show_error("Manual encryption crash", e)

    def logic_manual_decrypt(self):
        try:
            input_hex = self.ui.text_manual_input.toPlainText().strip()
            if not input_hex: raise ValueError("Please enter the HEX ciphertext you want to decrypt.")
            
            engine = self._prepare_engine()
            cipher_bits = hex_to_lsb_bits(input_hex)
            msg_bits = engine.decrypt(cipher_bits)
            
            self.ui.text_manual_output.setText(lsb_bits_to_string(msg_bits))
        except Exception as e:
            self.show_error("Manual decryption crash", e)

    def logic_file_load(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", "All Files (*)")
        if file_name: self.ui.input_file_path.setText(file_name)

    def logic_file_save_dir(self):
        is_encrypt = self.ui.radioButton_4.isChecked()
        dialog_title = "Set save path (for encrypted files)" if is_encrypt else "Set the save path (for decrypted files)."
        file_filter = "Encrypted Files (*.enc)" if is_encrypt else "Decrypted Files (*.dec)"
        
        file_name, _ = QFileDialog.getSaveFileName(self, dialog_title, "", file_filter)
        if file_name:
            if is_encrypt and not file_name.endswith(".enc"):
                file_name += ".enc"
            elif not is_encrypt and not file_name.endswith(".dec"):
                file_name += ".dec"
            self.ui.output_file_path.setText(file_name)

    def logic_file_encrypt(self):
        try:
            in_path = self.ui.input_file_path.text()
            out_path = self.ui.output_file_path.text()
            if not in_path or not out_path: raise ValueError("Please set the input and output paths first!")
            
            engine = self._prepare_engine()
            with open(in_path, 'r', encoding='utf-8') as f:
                plaintext = f.read()
                
            msg_bits = string_to_lsb_bits(plaintext)
            cipher_bits = engine.encrypt(msg_bits)
            cipher_hex = lsb_bits_to_hex(cipher_bits)
            
            self.file_handler.save_encrypted_file(self.ui.input_iv.text(), cipher_hex, out_path)
            QMessageBox.information(self, "Success", "File encryption and IV packaging successful!")
        except Exception as e:
            self.show_error("File encryption failed.", e)

    def logic_file_decrypt(self):
        try:
            in_path = self.ui.input_file_path.text()
            out_path = self.ui.output_file_path.text()
            if not in_path or not out_path: raise ValueError("Please set the input and output paths first!")
            
            loaded_iv, cipher_hex = self.file_handler.load_encrypted_file(in_path)
            self.ui.input_iv.setText(loaded_iv) 
            
            engine = self._prepare_engine()
            cipher_bits = hex_to_lsb_bits(cipher_hex)
            msg_bits = engine.decrypt(cipher_bits)
            plaintext = lsb_bits_to_string(msg_bits)
            
            self.file_handler.save_decrypted_file(plaintext, out_path)
            QMessageBox.information(self, "Success", "File decryption successful!")
        except Exception as e:
            self.show_error("File decryption failed.", e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GrainApp()
    window.show()
    sys.exit(app.exec())