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
        # 区块 1
        self.ui.btn_generate_key.clicked.connect(self.logic_generate_key)
        self.ui.btn_wrap_save.clicked.connect(self.logic_wrap_key)
        self.ui.btn_load_key.clicked.connect(self.logic_unwrap_key)
        
        # 区块 2
        self.ui.btn_generate_iv.clicked.connect(self.logic_generate_iv)

        # 区块 3 (文件)
        self.ui.btn_file_load.clicked.connect(self.logic_file_load)
        self.ui.btn_file_save.clicked.connect(self.logic_file_save_dir)
        self.ui.btn_file_encrypt.clicked.connect(self.logic_file_encrypt)
        self.ui.btn_file_decrypt.clicked.connect(self.logic_file_decrypt)

        # 区块 3 (手动)
        self.ui.btn_manual_encrypt.clicked.connect(self.logic_manual_encrypt)
        self.ui.btn_manual_decrypt.clicked.connect(self.logic_manual_decrypt)

        # UI联动互锁机制
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

    # ================= 辅助函数 =================
    def show_error(self, title, exception_obj):
        error_details = traceback.format_exc()
        print(f"\n{'='*20} ❌ {title} {'='*20}")
        print(error_details)
        print("========================================================\n")
        
        error_msg = str(exception_obj).strip()
        if "non-hexadecimal" in error_msg:
            error_msg = "输入了非法的十六进制字符 (请检查是否混入了普通字母或多余空格)！"
        elif not error_msg: 
            # 强制抓取对象的原生描述，解决弹窗没字的问题
            error_msg = repr(exception_obj) 
            
        QMessageBox.critical(self, title, f"操作失败！\n\n简述原因: {error_msg}\n\n(详尽报错日志已打印至控制台终端，请切换查看)")

    def _prepare_engine(self):
        key_hex = self.ui.input_key.text().strip().replace("0x", "")
        iv_hex = self.ui.input_iv.text().strip().replace("0x", "")
        
        if len(key_hex) != 32:
            raise ValueError(f"Key 长度错误！必须是32位Hex字符(128-bit)，当前为 {len(key_hex)} 位。")
        if len(iv_hex) != 24:
            raise ValueError(f"IV 长度错误！必须是24位Hex字符(96-bit)，当前为 {len(iv_hex)} 位。")
            
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

    # ================= 核心业务逻辑 =================

    def logic_generate_key(self):
        self.ui.input_key.setText("0x" + self.key_manager.generate_random_key_hex())

    def logic_generate_iv(self):
        if self.ui.check_auto_iv.isChecked():
            self.ui.input_iv.setText("0x" + secrets.token_hex(12)) 
        else:
            QMessageBox.warning(self, "操作被拒", "必须先勾选 'Automatically Generate unique IV' 才能自动生成。")

    def logic_wrap_key(self):
        try:
            pwd = self.ui.input_password.text()
            key_hex = self.ui.input_key.text()
            ad = self.ui.input_ad.text().strip()
            
            if not pwd or not key_hex:
                raise ValueError("Password 和 Key 不能为空。")
            
            is_hex = (self.ui.combo_ad_mode.currentText() == "Hex")
            
            if is_hex and ad:
                try:
                    bytes.fromhex(ad.replace("0x", ""))
                except ValueError:
                    raise ValueError("AD 格式冲突：您选择了 Hex 模式，但输入了非十六进制的普通字符！")

            wrapped_data = self.key_manager.wrap_key(pwd, key_hex, ad, is_hex)
            
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Wrapped Key", "", "Key Files (*.key)")
            if save_path:
                # 强制补全后缀
                if not save_path.endswith(".key"):
                    save_path += ".key"
                self.file_handler.save_key_file(wrapped_data, save_path)
                QMessageBox.information(self, "成功", "密钥已成功加密(Wrap)并保存到文件！")
        except Exception as e:
            self.show_error("Key Wrapping 失败", e)

    def logic_unwrap_key(self):
        try:
            pwd = self.ui.input_password.text()
            ad = self.ui.input_ad.text().strip()
            
            if not pwd:
                raise ValueError("解密 Key 文件必须输入 Password。")
                
            load_path, _ = QFileDialog.getOpenFileName(self, "Load Wrapped Key", "", "Key Files (*.key)")
            if load_path:
                is_hex = (self.ui.combo_ad_mode.currentText() == "Hex")
                key_data = self.file_handler.load_key_file(load_path)
                unwrapped_key_hex = self.key_manager.unwrap_key(pwd, key_data, ad, is_hex)
                
                self.ui.input_key.setText("0x" + unwrapped_key_hex)
                QMessageBox.information(self, "成功", "密钥已从文件中解密(Unwrap)并加载至控制台。")
        except Exception as e:
            self.show_error("Key Unwrapping 失败", e)

    def logic_manual_encrypt(self):
        try:
            input_text = self.ui.text_manual_input.toPlainText()
            if not input_text: raise ValueError("请输入需要加密的 ASCII 明文。")
            
            engine = self._prepare_engine()
            msg_bits = string_to_lsb_bits(input_text)
            cipher_bits = engine.encrypt(msg_bits)
            
            self.ui.text_manual_output.setText(lsb_bits_to_hex(cipher_bits))
        except Exception as e:
            self.show_error("手动加密崩溃", e)

    def logic_manual_decrypt(self):
        try:
            input_hex = self.ui.text_manual_input.toPlainText().strip()
            if not input_hex: raise ValueError("请输入需要解密的 HEX 密文。")
            
            engine = self._prepare_engine()
            cipher_bits = hex_to_lsb_bits(input_hex)
            msg_bits = engine.decrypt(cipher_bits)
            
            self.ui.text_manual_output.setText(lsb_bits_to_string(msg_bits))
        except Exception as e:
            self.show_error("手动解密崩溃", e)

    def logic_file_load(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", "All Files (*)")
        if file_name: self.ui.input_file_path.setText(file_name)

    def logic_file_save_dir(self):
        is_encrypt = self.ui.radioButton_4.isChecked()
        dialog_title = "设置保存路径 (加密文件)" if is_encrypt else "设置保存路径 (解密文件)"
        file_filter = "Encrypted Files (*.enc)" if is_encrypt else "Decrypted Files (*.dec)"
        
        file_name, _ = QFileDialog.getSaveFileName(self, dialog_title, "", file_filter)
        if file_name:
            # 强制按模式补全相应的后缀
            if is_encrypt and not file_name.endswith(".enc"):
                file_name += ".enc"
            elif not is_encrypt and not file_name.endswith(".dec"):
                file_name += ".dec"
            self.ui.output_file_path.setText(file_name)

    def logic_file_encrypt(self):
        try:
            in_path = self.ui.input_file_path.text()
            out_path = self.ui.output_file_path.text()
            if not in_path or not out_path: raise ValueError("请先设置输入和输出路径！")
            
            engine = self._prepare_engine()
            with open(in_path, 'r', encoding='utf-8') as f:
                plaintext = f.read()
                
            msg_bits = string_to_lsb_bits(plaintext)
            cipher_bits = engine.encrypt(msg_bits)
            cipher_hex = lsb_bits_to_hex(cipher_bits)
            
            self.file_handler.save_encrypted_file(self.ui.input_iv.text(), cipher_hex, out_path)
            QMessageBox.information(self, "成功", "文件加密并打包IV成功！")
        except Exception as e:
            self.show_error("文件加密失败", e)

    def logic_file_decrypt(self):
        try:
            in_path = self.ui.input_file_path.text()
            out_path = self.ui.output_file_path.text()
            if not in_path or not out_path: raise ValueError("请先设置输入和输出路径！")
            
            loaded_iv, cipher_hex = self.file_handler.load_encrypted_file(in_path)
            self.ui.input_iv.setText(loaded_iv) 
            
            engine = self._prepare_engine()
            cipher_bits = hex_to_lsb_bits(cipher_hex)
            msg_bits = engine.decrypt(cipher_bits)
            plaintext = lsb_bits_to_string(msg_bits)
            
            self.file_handler.save_decrypted_file(plaintext, out_path)
            QMessageBox.information(self, "成功", "文件解密成功！")
        except Exception as e:
            self.show_error("文件解密失败", e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GrainApp()
    window.show()
    sys.exit(app.exec())