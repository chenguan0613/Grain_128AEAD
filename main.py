import tkinter as tk
from tkinter import messagebox, filedialog
import os
import secrets

from key_management.wrapper import KeyManager
from file_io.file_handler import FileHandler

# --- 统一的 UI 配色方案 (深色极客风) ---
BG_COLOR = "#2C3E50"      # 主背景深灰蓝
PANEL_BG = "#34495E"      # 面板底色
TEXT_FG = "#ECF0F1"       # 文字白
BTN_COLOR = "#2980B9"     # 按钮蓝
BTN_ACTION = "#16A085"    # 重点操作按钮绿
HL_COLOR = "#E67E22"      # 高亮橙色

class GrainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GRAIN-128AEAD Software Suite - By XMUM Cyber Security")
        self.root.geometry("1000x750") 
        self.root.configure(bg=BG_COLOR)

        if not os.path.exists("data"):
            os.makedirs("data")

        self.key_manager = KeyManager()

        # ==========================================
        # 核心布局：左右两大列 (完全匹配 Figure 1)
        # ==========================================
        main_container = tk.Frame(self.root, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        left_col = tk.Frame(main_container, bg=BG_COLOR)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 5))

        right_col = tk.Frame(main_container, bg=BG_COLOR)
        right_col.pack(side="right", fill="both", expand=True, padx=(5, 0))

        # 依次初始化四大区块
        self.setup_block_1_key(left_col)
        self.setup_block_4_monitor(left_col)
        
        self.setup_block_2_iv(right_col)
        self.setup_block_3_workflow(right_col)

    # ==========================================
    # 区块 1: KEY MANAGEMENT (左上)
    # ==========================================
    def setup_block_1_key(self, parent):
        frame = tk.LabelFrame(parent, text=" 1 KEY MANAGEMENT (128-bit Secret Key, K_Grain) ", 
                              bg=PANEL_BG, fg=HL_COLOR, font=("Arial", 10, "bold"))
        frame.pack(fill="x", pady=(0, 10), ipady=5)

        tk.Label(frame, text="Hex Key Input (K_Grain)", bg=PANEL_BG, fg=TEXT_FG).grid(row=0, column=0, sticky="w", padx=10)
        self.entry_grain_key = tk.Entry(frame, width=38, bg="#1A252F", fg=TEXT_FG, insertbackground="white")
        self.entry_grain_key.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        tk.Button(frame, text="GENERATE KEY", bg=BTN_COLOR, fg="white", font=("Arial", 9, "bold"), 
                  command=self.generate_key).grid(row=1, column=1, padx=5)

        # 打包区
        wrap_frame = tk.LabelFrame(frame, text=" KEY WRAPPING & STORAGE ", bg=PANEL_BG, fg=TEXT_FG)
        wrap_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        tk.Label(wrap_frame, text="Password for Wrapping", bg=PANEL_BG, fg=TEXT_FG).grid(row=0, column=0, sticky="w")
        self.entry_password = tk.Entry(wrap_frame, show="*", width=20, bg="#1A252F", fg=TEXT_FG)
        self.entry_password.grid(row=1, column=0, padx=5, sticky="w")

        tk.Label(wrap_frame, text="Associated Data (AD)", bg=PANEL_BG, fg=TEXT_FG).grid(row=0, column=1, sticky="w")
        self.entry_ad = tk.Entry(wrap_frame, width=20, bg="#1A252F", fg=TEXT_FG)
        self.entry_ad.grid(row=1, column=1, padx=5, sticky="w")

        tk.Button(wrap_frame, text="🔒 WRAP & SAVE .KEY FILE", bg=BTN_ACTION, fg="white", 
                  command=self.wrap_and_save).grid(row=2, column=0, pady=10, padx=5, sticky="we")
        tk.Button(wrap_frame, text="📂 LOAD .KEY FILE", bg=BTN_ACTION, fg="white", 
                  command=self.load_and_unwrap).grid(row=2, column=1, pady=10, padx=5, sticky="we")

    # ==========================================
    # 区块 4: ALGORITHM INTERNAL STATES MONITOR (左下)
    # ==========================================
    def setup_block_4_monitor(self, parent):
        frame = tk.LabelFrame(parent, text=" 4 ALGORITHM INTERNAL STATES MONITOR ", 
                              bg=PANEL_BG, fg=HL_COLOR, font=("Arial", 10, "bold"))
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="States After Loading", bg=PANEL_BG, fg=TEXT_FG).pack(anchor="w", padx=10, pady=(10,0))
        self.entry_nfsr_load = tk.Entry(frame, width=45, state="readonly")
        self.entry_nfsr_load.pack(padx=10, pady=2)
        self.entry_lfsr_load = tk.Entry(frame, width=45, state="readonly")
        self.entry_lfsr_load.pack(padx=10, pady=2)

        tk.Label(frame, text="States After Initialization", bg=PANEL_BG, fg=TEXT_FG).pack(anchor="w", padx=10, pady=(10,0))
        self.entry_nfsr_init = tk.Entry(frame, width=45, state="readonly")
        self.entry_nfsr_init.pack(padx=10, pady=2)
        self.entry_lfsr_init = tk.Entry(frame, width=45, state="readonly")
        self.entry_lfsr_init.pack(padx=10, pady=2)

    # ==========================================
    # 区块 2: NONCE/IV MANAGEMENT (右上)
    # ==========================================
    def setup_block_2_iv(self, parent):
        frame = tk.LabelFrame(parent, text=" 2 NONCE/IV MANAGEMENT (96-bit, V_Grain) ", 
                              bg=PANEL_BG, fg=HL_COLOR, font=("Arial", 10, "bold"))
        frame.pack(fill="x", pady=(0, 10), ipady=5)

        tk.Label(frame, text="Hex Nonce Input (V_Grain)", bg=PANEL_BG, fg=TEXT_FG).grid(row=0, column=0, sticky="w", padx=10)
        self.entry_iv = tk.Entry(frame, width=38, bg="#1A252F", fg=TEXT_FG, insertbackground="white")
        self.entry_iv.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        tk.Button(frame, text="GENERATE IV", bg=BTN_COLOR, fg="white", font=("Arial", 9, "bold"), 
                  command=self.generate_iv).grid(row=1, column=1, padx=5)

    # ==========================================
    # 区块 3: ENCRYPTION & DECRYPTION WORKFLOWS (右下)
    # ==========================================
    def setup_block_3_workflow(self, parent):
        frame = tk.LabelFrame(parent, text=" 3 ENCRYPTION & DECRYPTION WORKFLOWS ", 
                              bg=PANEL_BG, fg=HL_COLOR, font=("Arial", 10, "bold"))
        frame.pack(fill="both", expand=True)

        # 顶部的动作按钮区
        action_frame = tk.Frame(frame, bg=PANEL_BG)
        action_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(action_frame, text="LOAD PLAINTEXT FILE (for Enc.)", bg=BTN_COLOR, fg="white").grid(row=0, column=0, padx=5, pady=5)
        tk.Button(action_frame, text="LOAD .ENC FILE (for Dec.)", bg=BTN_COLOR, fg="white").grid(row=1, column=0, padx=5, pady=5)
        
        tk.Button(action_frame, text="🔥 ENCRYPT", bg="#E74C3C", fg="white", font=("Arial", 10, "bold"), width=15,
                  command=self.do_encrypt).grid(row=0, column=1, padx=20, rowspan=2, ipady=10)

        # 输入输出文本框区
        tk.Label(frame, text="Manual Input (Plaintext / Ciphertext)", bg=PANEL_BG, fg=TEXT_FG).pack(anchor="w", padx=10)
        self.text_input = tk.Text(frame, height=5, bg="#1A252F", fg=TEXT_FG, insertbackground="white")
        self.text_input.pack(fill="x", padx=10, pady=5)

        tk.Label(frame, text="Output Terminal (Hex / ASCII)", bg=PANEL_BG, fg=TEXT_FG).pack(anchor="w", padx=10)
        self.text_output = tk.Text(frame, height=5, bg="#1A252F", fg="#2ECC71", insertbackground="white")
        self.text_output.pack(fill="x", padx=10, pady=5)

        # 底部保存按钮
        save_frame = tk.Frame(frame, bg=PANEL_BG)
        save_frame.pack(fill="x", padx=10, pady=10)
        tk.Button(save_frame, text="💾 SAVE .ENC FILE", bg=BTN_ACTION, fg="white").pack(side="left", expand=True, fill="x", padx=5)
        tk.Button(save_frame, text="💾 SAVE .DEC FILE", bg=BTN_ACTION, fg="white").pack(side="right", expand=True, fill="x", padx=5)

    # ==========================================
    # 基础逻辑绑定
    # ==========================================
    def generate_key(self):
        self.entry_grain_key.delete(0, tk.END)
        self.entry_grain_key.insert(0, self.key_manager.generate_random_key_hex())

    def generate_iv(self):
        # IV 是 96-bit，对应 12 bytes = 24 个十六进制字符
        self.entry_iv.delete(0, tk.END)
        self.entry_iv.insert(0, secrets.token_hex(12))

    def wrap_and_save(self):
        key = self.entry_grain_key.get().strip()
        pwd = self.entry_password.get().strip()
        ad = self.entry_ad.get().strip()
        if not key or not pwd:
            messagebox.showerror("Error", "Key and Password required!")
            return
        filepath = filedialog.asksaveasfilename(initialdir="data", defaultextension=".key")
        if filepath:
            FileHandler.save_key_file(self.key_manager.wrap_key(pwd, key, ad), filepath)
            messagebox.showinfo("Success", "Key wrapped and saved!")

    def load_and_unwrap(self):
        pwd = self.entry_password.get().strip()
        ad = self.entry_ad.get().strip()
        if not pwd:
            messagebox.showerror("Error", "Password required!")
            return
        filepath = filedialog.askopenfilename(initialdir="data", filetypes=[("Key Files", "*.key")])
        if filepath:
            try:
                rec_key = self.key_manager.unwrap_key(pwd, FileHandler.load_key_file(filepath), ad)
                self.entry_grain_key.delete(0, tk.END)
                self.entry_grain_key.insert(0, rec_key)
                messagebox.showinfo("Success", "Key Unwrapped!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def do_encrypt(self):
        # 这里预留给下一步接入 Grain 引擎！
        messagebox.showinfo("Wait!", "界面已经就绪！下一步我们将把 Grain 引擎接入这个按钮，进行真正的加密！")


if __name__ == "__main__":
    root = tk.Tk()
    app = GrainApp(root)
    root.mainloop()