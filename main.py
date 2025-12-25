import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_manager import RSAHandler 

# --- GIAO DIỆN NGƯỜI GỬI ---
class SenderWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("BÊN GỬI - TẠO KHÓA & KÝ")
        self.geometry("600x750")
        self.rsa = RSAHandler()
        self.setup_ui()

    def setup_ui(self):
        # --- PHẦN 1: THIẾT LẬP KHÓA (TỰ ĐỘNG & THỦ CÔNG) ---
        frame_gen = tk.LabelFrame(self, text=" 1. Thiết lập Khóa RSA ", padx=10, pady=10)
        frame_gen.pack(fill="x", padx=10, pady=5)

        # Dòng 1: Tạo tự động
        tk.Label(frame_gen, text="Key Size (bits):").grid(row=0, column=0, sticky="w")
        self.ent_size = tk.Entry(frame_gen, width=15)
        self.ent_size.insert(0, "2048")
        self.ent_size.grid(row=0, column=1, padx=5)
        tk.Button(frame_gen, text="Tạo Tự Động", command=self.gen_auto, bg="#e0e0e0").grid(row=0, column=2, padx=5)

        # Dòng 2: Tạo thủ công (Cách ra một chút cho thoáng)
        tk.Label(frame_gen, text="-------------------------------------------------").grid(row=1, column=0, columnspan=5, pady=5)
        
        tk.Label(frame_gen, text="P (Prime 1):").grid(row=2, column=0, sticky="w")
        self.ent_p = tk.Entry(frame_gen, width=15)
        self.ent_p.grid(row=2, column=1, padx=5)
        
        tk.Label(frame_gen, text="Q (Prime 2):").grid(row=2, column=2, sticky="w")
        self.ent_q = tk.Entry(frame_gen, width=15)
        self.ent_q.grid(row=2, column=3, padx=5)
        
        tk.Button(frame_gen, text="Tạo Thủ Công", command=self.gen_manual, bg="#ffe0b2").grid(row=2, column=4, padx=5)

        # --- PHẦN HIỂN THỊ THAM SỐ (CÓ THANH CUỘN) ---
        tk.Label(self, text="Tham số chi tiết (P, Q, N, E, D):").pack(anchor="w", padx=15, pady=(10, 0))
        
        # Tạo Frame chứa Text và Scrollbar
        frame_display = tk.Frame(self)
        frame_display.pack(fill="x", padx=15, pady=5)

        scrollbar = tk.Scrollbar(frame_display)
        scrollbar.pack(side="right", fill="y")

        # Liên kết Text với Scrollbar
        self.txt_params = tk.Text(frame_display, height=10, bg="#f5f5f5", yscrollcommand=scrollbar.set)
        self.txt_params.pack(side="left", fill="both", expand=True)
        
        scrollbar.config(command=self.txt_params.yview)
        
        # Nút lưu khóa
        tk.Button(self, text="Lưu Cặp Khóa (.pem)", command=self.save_k, bg="#bdbdbd").pack(pady=5)

        # --- PHẦN 2: TẠO CHỮ KÝ ---
        frame_sign = tk.LabelFrame(self, text=" 2. Tạo Chữ Ký ", padx=10, pady=10)
        frame_sign.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(frame_sign, text="Nhập văn bản hoặc chọn file:").pack(anchor="w")
        self.txt_content = tk.Text(frame_sign, height=5)
        self.txt_content.pack(fill="x", pady=5)

        btn_box = tk.Frame(frame_sign)
        btn_box.pack()
        tk.Button(btn_box, text="Ký Văn Bản", command=self.sign_txt).pack(side="left", padx=5)
        tk.Button(btn_box, text="Ký File Bất Kỳ", command=self.sign_file).pack(side="left", padx=5)

        tk.Label(frame_sign, text="Chữ ký (Base64):").pack(anchor="w")
        self.txt_sig = tk.Text(frame_sign, height=4, bg="#e8f5e9")
        self.txt_sig.pack(fill="x")
        
        # --- PHẦN 3: CÁC NÚT LƯU RIÊNG BIỆT ---
        frame_save = tk.Frame(self)
        frame_save.pack(pady=10)
        
        tk.Button(frame_save, text="Lưu Nội Dung Văn Bản (.txt)", 
                  command=self.save_text_content, bg="#bbdefb", height=2).pack(side="left", padx=10)
                  
        tk.Button(frame_save, text="Lưu File Chữ Ký (.sig)", 
                  command=self.save_signature_file, bg="#ffccbc", height=2).pack(side="left", padx=10)

    def gen_auto(self):
        try:
            size = int(self.ent_size.get())
            # Lưu ý: Hàm generate_keys_with_params phải tồn tại trong crypto_manager.py
            params = self.rsa.generate_keys_with_params(key_size=size)
            self.display_params(params)
        except Exception as e: messagebox.showerror("Lỗi", f"Lỗi tạo khóa: {str(e)}")

    def gen_manual(self):
        try:
            p = int(self.ent_p.get())
            q = int(self.ent_q.get())
            self.rsa.load_manual_key(p, q, 65537)
            self.display_params(self.rsa.get_internal_params())
        except Exception as e: messagebox.showerror("Lỗi", f"Tham số sai: {e}")

    def display_params(self, p):
        self.txt_params.delete("1.0", tk.END)
        if p:
            # Định dạng chuỗi hiển thị rõ ràng từng thành phần
            text = (
                f"=== [1] SỐ NGUYÊN TỐ BÍ MẬT ===\n"
                f"P = {p['p']}\n\n"
                f"Q = {p['q']}\n\n"
                f"=== [2] KHÓA CÔNG KHAI (Public Key) ===\n"
                f"N (Modulus = P x Q) = {p['n']}\n\n"
                f"E (Exponent) = {p['e']}\n\n"
                f"=== [3] KHÓA BÍ MẬT (Private Key) ===\n"
                f"D (Được tính từ nghịch đảo của E) = {p['d']}"
            )
            self.txt_params.insert(tk.END, text)

    def save_k(self):
        folder = filedialog.askdirectory()
        if folder and self.rsa.save_keys(folder): 
            messagebox.showinfo("OK", "Đã lưu private_key.pem và public_key.pem")

    def sign_txt(self):
        data = self.txt_content.get("1.0", tk.END).strip().encode()
        if data: self._do_sign(data)

    def sign_file(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, "rb") as f: self._do_sign(f.read())

    def _do_sign(self, data):
        try:
            sig = self.rsa.sign(data)
            self.txt_sig.delete("1.0", tk.END)
            self.txt_sig.insert(tk.END, sig)
        except Exception as e: messagebox.showerror("Lỗi", f"Chưa có khóa hoặc lỗi ký: {str(e)}")

    # --- CÁC HÀM LƯU RIÊNG BIỆT ---
    def save_text_content(self):
        content = self.txt_content.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Trống", "Không có nội dung văn bản để lưu!")
            return
        
        path = filedialog.asksaveasfilename(defaultextension=".txt", title="Lưu nội dung văn bản")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Xong", "Đã lưu file văn bản thành công!")

    def save_signature_file(self):
        sig = self.txt_sig.get("1.0", tk.END).strip()
        if not sig:
            messagebox.showwarning("Trống", "Chưa có chữ ký để lưu!")
            return
            
        path = filedialog.asksaveasfilename(defaultextension=".sig", title="Lưu file chữ ký")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(sig)
            messagebox.showinfo("Xong", "Đã lưu file chữ ký thành công!")

# --- GIAO DIỆN NGƯỜI NHẬN 
class ReceiverWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("BÊN NHẬN - KIỂM TRA")
        self.geometry("600x750") # Tăng chiều cao một chút
        self.rsa = RSAHandler()
        self.setup_ui()

    def setup_ui(self):
        # 1. Khu vực Nạp Khóa
        frame_k = tk.LabelFrame(self, text=" 1. Nạp Khóa Công Khai (Public Key) ", padx=10, pady=10)
        frame_k.pack(fill="x", padx=10, pady=5)
        
        tk.Button(frame_k, text="Chọn file Public Key (.pem)", command=self.load_pub, bg="#e3f2fd").pack(pady=5)
        
        tk.Label(frame_k, text="Thông tin khóa (N, E):").pack(anchor="w")

        # --- Tạo khung hiển thị có thanh cuộn (Scrollbar) ---
        frame_pub_display = tk.Frame(frame_k)
        frame_pub_display.pack(fill="x", pady=5)
        
        scrollbar_pub = tk.Scrollbar(frame_pub_display)
        scrollbar_pub.pack(side="right", fill="y")
        
        # Ô text hiển thị N và E
        self.txt_pub_display = tk.Text(frame_pub_display, height=8, bg="#f5f5f5", font=("Courier", 9), yscrollcommand=scrollbar_pub.set)
        self.txt_pub_display.pack(side="left", fill="both", expand=True)
        
        scrollbar_pub.config(command=self.txt_pub_display.yview)
        # --------------------------------------------------

        # 2. Khu vực Kiểm tra
        frame_v = tk.LabelFrame(self, text=" 2. Nhập Dữ Liệu & Chữ Ký ", padx=10, pady=10)
        frame_v.pack(fill="both", expand=True, padx=10, pady=5)

        tk.Label(frame_v, text="Nội dung văn bản (hoặc nạp từ file .txt):").pack(anchor="w")
        tk.Button(frame_v, text="Mở file văn bản (.txt)", command=self.load_text_file, font=("Arial", 8)).pack(anchor="e", padx=5)
        
        self.txt_data = tk.Text(frame_v, height=5)
        self.txt_data.pack(fill="x", pady=5)

        tk.Label(frame_v, text="Chữ ký (Base64) hoặc nạp file chữ ký (.sig):").pack(anchor="w")
        self.ent_sig = tk.Entry(frame_v)
        self.ent_sig.pack(fill="x", pady=5)
        
        tk.Button(frame_v, text="Nạp file Chữ ký (.sig)", command=self.load_sig_file).pack()

        btn_row = tk.Frame(self)
        btn_row.pack(pady=10)
        tk.Button(btn_row, text="KIỂM TRA VĂN BẢN", command=self.val_txt, bg="#ffc107", height=2).pack(side="left", padx=10)
        tk.Button(btn_row, text="KIỂM TRA FILE GỐC", command=self.val_file, bg="#03a9f4", height=2).pack(side="left", padx=10)

    def load_pub(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        # Gọi hàm load_public_key từ logic
        if path and self.rsa.load_public_key(path):
            # Lấy thông tin chi tiết N và E
            details = self.rsa.get_public_key_details()
            
            if details:
                # Định dạng hiển thị đẹp mắt
                display_text = (
                    f"=== THÔNG SỐ KHÓA CÔNG KHAI ===\n\n"
                    f"[Modulus N] (Dùng để xác thực chữ ký):\n{details['n']}\n\n"
                    f"[Exponent E] (Số mũ công khai):\n{details['e']}"
                )
                self.txt_pub_display.delete("1.0", tk.END)
                self.txt_pub_display.insert(tk.END, display_text)
                messagebox.showinfo("Thành công", "Đã nạp khóa! Hãy kiểm tra số N có khớp với bên Gửi không.")
            else:
                 self.txt_pub_display.insert(tk.END, "Không đọc được thông số khóa.")
        else:
            messagebox.showerror("Lỗi", "File khóa không hợp lệ hoặc chưa chọn file.")

    def load_text_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.txt_data.delete("1.0", tk.END)
                self.txt_data.insert(tk.END, f.read())

    def load_sig_file(self):
        path = filedialog.askopenfilename(filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8") as f: 
                self.ent_sig.delete(0, tk.END)
                self.ent_sig.insert(0, f.read().strip())

    def val_txt(self):
        data = self.txt_data.get("1.0", tk.END).strip().encode()
        self._verify(data)

    def val_file(self):
        path = filedialog.askopenfilename(title="Chọn file gốc để đối chiếu")
        if path:
            with open(path, "rb") as f: self._verify(f.read())

    def _verify(self, data):
        sig = self.ent_sig.get().strip()
        # Gọi hàm verify_detailed đã tách lỗi
        code, msg = self.rsa.verify_detailed(data, sig)
        
        if code == "SUCCESS":
            messagebox.showinfo("KẾT QUẢ: HỢP LỆ", msg)
        elif code == "ERR_SIG_LENGTH":
            messagebox.showerror("LỖI CHỮ KÝ", msg)
        elif code == "ERR_SIG_FORMAT":
             messagebox.showerror("LỖI ĐỊNH DẠNG", msg)
        else:
            messagebox.showerror("CẢNH BÁO: KHÔNG KHỚP", msg)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("RSA System")
    root.geometry("350x200")
    
    label = tk.Label(root, text="CHƯƠNG TRÌNH CHỮ KÝ SỐ RSA", font=("Arial", 14, "bold"))
    label.pack(pady=20)
    
    tk.Button(root, text="GIAO DIỆN NGƯỜI GỬI", command=lambda: SenderWindow(root), height=2, width=25, bg="#c8e6c9").pack(pady=10)
    tk.Button(root, text="GIAO DIỆN NGƯỜI NHẬN", command=lambda: ReceiverWindow(root), height=2, width=25, bg="#bbdefb").pack(pady=10)
    root.mainloop()