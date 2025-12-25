import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class RSAHandler:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys_with_params(self, key_size=2048, public_exponent=65537):
        """Tạo khóa tự động và trả về tham số"""
        if key_size < 1024:
            raise ValueError("Key size quá nhỏ (nên >= 1024)")
        self.private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        return self.get_internal_params()

    def get_internal_params(self):
        """Lấy tham số P, Q, N, E, D để hiển thị cho Người Gửi"""
        if not self.private_key: return None
        pn = self.private_key.private_numbers()
        return {
            "p": pn.p, "q": pn.q, "d": pn.d,
            "n": pn.public_numbers.n, "e": pn.public_numbers.e
        }
    
    def get_public_key_details(self):
        """Lấy tham số N và E để hiển thị cho Người Nhận (Hàm bạn đang thiếu)"""
        if not self.public_key: return None
        pn = self.public_key.public_numbers()
        return {
            "n": pn.n, 
            "e": pn.e 
        }

    def load_manual_key(self, p, q, e):
        """Tạo khóa từ P, Q nhập tay"""
        try:
            n = p * q
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            dmp1 = d % (p - 1)
            dmq1 = d % (q - 1)
            iqmp = pow(q, -1, p)
            public_numbers = rsa.RSAPublicNumbers(e, n)
            private_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers)
            self.private_key = private_numbers.private_key()
            self.public_key = self.private_key.public_key()
            return True
        except Exception as ex:
            raise ValueError(f"Thông số p, q, e không hợp lệ: {ex}")

    def save_keys(self, folder_path):
        """Lưu cặp khóa ra file .pem"""
        if not self.private_key: return False
        try:
            os.makedirs(folder_path, exist_ok=True)
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(os.path.join(folder_path, "private_key.pem"), "wb") as f: f.write(priv_pem)
            with open(os.path.join(folder_path, "public_key.pem"), "wb") as f: f.write(pub_pem)
            return True
        except: return False

    def load_public_key(self, public_path):
        """Nạp Public Key từ file .pem"""
        try:
            with open(public_path, 'rb') as f:
                pem_data = f.read()
            self.public_key = serialization.load_pem_public_key(pem_data)
            return True
        except: return False

    def sign(self, data: bytes) -> str:
        """Ký số (Trả về Base64)"""
        if not self.private_key: raise ValueError("Chưa nạp Private Key")
        signature = self.private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_detailed(self, data: bytes, signature_b64: str):
        """Xác thực chữ ký và báo lỗi chi tiết"""
        if not self.public_key:
            return "ERR_KEY", "Chưa nạp Khóa công khai!"
        
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return "ERR_SIG_FORMAT", "LỖI CHỮ KÝ: Định dạng Base64 không hợp lệ."

        # Kiểm tra độ dài chữ ký (Mẹo phát hiện lỗi)
        key_size_bytes = self.public_key.key_size // 8
        if len(signature) != key_size_bytes:
            return "ERR_SIG_LENGTH", f"LỖI CHỮ KÝ: Sai kích thước (Cần {key_size_bytes} bytes, nhận {len(signature)} bytes)."

        try:
            self.public_key.verify(
                signature, data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return "SUCCESS", "Xác thực thành công! Dữ liệu nguyên vẹn."
        except Exception:
            return "ERR_MISMATCH", "LỖI VĂN BẢN: Nội dung đã bị thay đổi (hoặc sai khóa)."

    def get_pub_key_text(self):
        """Lấy nội dung PEM của Public Key (để hiển thị dạng text cũ nếu cần)"""
        if not self.public_key: return ""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()