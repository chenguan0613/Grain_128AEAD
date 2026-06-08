import tkinter as tk
from tkinter import messagebox, filedialog
import os

# 导入我们的底层核心模块
from key_management.wrapper import KeyManager
from file_io.file_handler import FileHandler

class GrainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GRAIN-128AEAD Software Suite")
        self.root.geometry("850x650") # 设置窗口大小
        
        # 响应你的好习惯：确保 data 文件夹存在，作为我们的默认工作目录
        if not os.path.exists("data"):
            os.makedirs("data")

        # 实例化我们的密钥管家
        self.key_manager = KeyManager()

        # ==========================================
        # 区块 1: KEY MANAGEMENT (密钥管理)
        # ==========================================
        self.setup_block_1()

    def setup_block_1(self):
        # 创建区块 1 的主边框
        frame1 = tk.LabelFrame(self.root, text="1 KEY MANAGEMENT (128-bit Secret Key)", padx=10, pady=10)
        frame1.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

        # --- 第一行：主密钥输入框与生成按钮 ---
        tk.Label(frame1, text="Hex Key Input (K_Grain)").grid(row=0, column=0, sticky="w")
        self.entry_grain_key = tk.Entry(frame1, width=35)
        self.entry_grain_key.grid(row=1, column=0, pady=5, sticky="w")
        
        btn_gen_key = tk.Button(frame1, text="GENERATE KEY", bg="teal", fg="white", command=self.generate_key)
        btn_gen_key.grid(row=1, column=1, padx=10)

        # --- 第二行：密钥打包与存储 (内部子框) ---
        wrap_frame = tk.LabelFrame(frame1, text="KEY WRAPPING & STORAGE", padx=10, pady=10)
        wrap_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

        # 密码输入区
        tk.Label(wrap_frame, text="Password for Wrapping").grid(row=0, column=0, sticky="w")
        self.entry_password = tk.Entry(wrap_frame, show="*", width=20)
        self.entry_password.grid(row=1, column=0, sticky="w", padx=5)

        # 附加数据 (AD) 输入区
        tk.Label(wrap_frame, text="Associated Data (AD)").grid(row=0, column=1, sticky="w")
        self.entry_ad = tk.Entry(wrap_frame, width=20)
        self.entry_ad.grid(row=1, column=1, sticky="w", padx=5)

        # AD 格式选择 (HEX / Text)
        self.ad_mode_var = tk.StringVar(value="Text")
        radio_frame = tk.Frame(wrap_frame)
        radio_frame.grid(row=2, column=1, sticky="w", pady=5)
        tk.Label(radio_frame, text="Input Mode:").pack(side="left")
        tk.Radiobutton(radio_frame, text="HEX", variable=self.ad_mode_var, value="HEX").pack(side="left")
        tk.Radiobutton(radio_frame, text="Text", variable=self.ad_mode_var, value="Text").pack(side="left")

        # 保存与加载按钮
        btn_wrap = tk.Button(wrap_frame, text="WRAP & SAVE .KEY FILE", command=self.wrap_and_save)
        btn_wrap.grid(row=3, column=0, pady=10, padx=5, sticky="we")

        btn_load = tk.Button(wrap_frame, text="LOAD .KEY FILE", command=self.load_and_unwrap)
        btn_load.grid(row=3, column=1, pady=10, padx=5, sticky="we")

    # ==========================================
    # 按钮绑定的功能逻辑 (连接前几个阶段的成果)
    # ==========================================
    def generate_key(self):
        """点击生成按钮：一键生成随机主密钥填入输入框"""
        new_key = self.key_manager.generate_random_key_hex()
        self.entry_grain_key.delete(0, tk.END)
        self.entry_grain_key.insert(0, new_key)

    def wrap_and_save(self):
        """点击保存按钮：抓取界面的值 -> 打包 -> 弹窗保存文件"""
        grain_key = self.entry_grain_key.get().strip()
        password = self.entry_password.get().strip()
        ad_data = self.entry_ad.get().strip()
        is_hex = (self.ad_mode_var.get() == "HEX")

        if not grain_key or not password:
            messagebox.showerror("错误", "密钥和密码不能为空！")
            return

        # 动用阶段三打包
        key_dict = self.key_manager.wrap_key(password, grain_key, ad_data, ad_is_hex=is_hex)
        
        # 唤起系统的“保存文件”对话框 (默认指向 data 文件夹)
        filepath = filedialog.asksaveasfilename(initialdir="data", defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if filepath:
            # 动用阶段四代码落盘
            FileHandler.save_key_file(key_dict, filepath)
            messagebox.showinfo("成功", "主密钥已打包并存入 .key 文件！")

    def load_and_unwrap(self):
        """点击加载按钮：选文件 -> 校验密码和AD -> 吐出密钥填回框内"""
        password = self.entry_password.get().strip()
        ad_data = self.entry_ad.get().strip()
        is_hex = (self.ad_mode_var.get() == "HEX")

        if not password:
            messagebox.showerror("错误", "解封文件前，必须先填写对应的 Password！")
            return

        # 唤起系统的“打开文件”对话框
        filepath = filedialog.askopenfilename(initialdir="data", filetypes=[("Key Files", "*.key")])
        if not filepath: return

        # GUI 层面需要使用 try-except 来捕捉由于密码错误导致的崩溃，转换为弹窗提示用户
        try:
            # 阶段四读取 + 阶段三解封
            key_dict = FileHandler.load_key_file(filepath)
            recovered_key = self.key_manager.unwrap_key(password, key_dict, ad_data, ad_is_hex=is_hex)
            
            # 还原成功，把它塞回第一个输入框里
            self.entry_grain_key.delete(0, tk.END)
            self.entry_grain_key.insert(0, recovered_key)
            messagebox.showinfo("解封成功", "密码和AD验证通过，主密钥已重现！")
        except Exception:
            messagebox.showerror("拦截提醒", "解封失败！可能是密码或AD不对，或者文件被篡改。")

# 启动图形化窗口
if __name__ == "__main__":
    root = tk.Tk()
    app = GrainApp(root)
    root.mainloop()