# Phần mềm Chữ ký số RSA (RSA Digital Signature App)

Đây là ứng dụng Python hỗ trợ tạo cặp khóa RSA, ký số văn bản/file và xác thực chữ ký số. Ứng dụng được xây dựng với mục đích học tập môn An toàn thông tin/An ninh mạng.

## 🚀 Tính năng chính
- **Tạo khóa RSA:**
  - Tự động (Key size: 1024, 2048, 3072 bits...).
  - **Thủ công (Nâng cao):** Nhập số nguyên tố P, Q để tự tạo khóa (dành cho demo thuật toán).
- **Hiển thị chi tiết:** Xem rõ các tham số $P, Q, N, E, D$ bên Gửi và $N, E$ bên Nhận.
- **Ký số:** Hỗ trợ ký văn bản nhập tay hoặc file bất kỳ (PDF, Word, Ảnh...).
- **Lưu trữ tách biệt:** Cho phép lưu file nội dung (.txt) và file chữ ký (.sig) riêng biệt.
- **Xác thực thông minh:** Hệ thống báo lỗi chi tiết (Sai định dạng, Sai chữ ký, hay Sai nội dung văn bản).

## 📦 Cài đặt

1. Đảm bảo máy tính đã cài Python.
2. Cài đặt thư viện `cryptography`:
   ```bash
   pip install cryptography