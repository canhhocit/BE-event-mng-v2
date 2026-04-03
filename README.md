# Event Management System (Hệ thống Quản lý Sự kiện & Bán vé)
Hệ thống phân quyền với các vai trò: `ADMIN`, `ORGANIZER` (Ban tổ chức), và `CUSTOMER` (Khách hàng).

## 🚀 Công nghệ & Tiêu chuẩn sử dụng
- **Java 17 / Spring Boot 3.x**
- **Spring Security & JWT**: Xác thực và ủy quyền phân quyền mạnh mẽ.
- **Spring Data JPA / Hibernate**: ORM tương tác với cơ sở dữ liệu.
- **Swagger / OpenAPI 3**: Document API tự động.
- **Multipart/form-data**: Hỗ trợ xử lý và lưu trữ file ảnh trực tiếp vào local server.

## 🎯 Các tính năng chính (Đã hoàn thiện)

### 1. Quản lý Tài khoản & Xác thực (Authentication)
- Đăng ký và Đăng nhập bằng JWT.
- Phân biệt rõ vai trò: Người dùng thường có thể mua vé (`CUSTOMER`), Ban tổ chức có thể tạo sự kiện (`ORGANIZER`), Quản trị viên (`ADMIN`).

### 2. Quản lý Sự kiện & Danh mục
- Thêm/Sửa/Xóa/Xem Danh mục sự kiện (Category).
- Tạo và Chỉnh sửa sự kiện: Upload trực tiếp banner/poster vào thư mục hệ thống (xử lý qua `MultipartFile`), liên kết ảnh thẳng với sự kiện.
- Quy trình xuất bản sự kiện: Sự kiện có trạng thái ngầm (`DRAFT`) và chỉ được hiển thị khi Ban tổ chức xác nhận (`PUBLISHED`).

### 3. Phân phối & Quản lý Loại Vé (Ticket Types)
- Mỗi sự kiện có thể có nhiều hạng vé khác nhau (Fanzone, VIP, Thường).
- Cho phép setup Số lượng tổng, tính toán số lượng vé còn lại trong kho theo thời gian thực (Inventory Management).

### 4. Giỏ hàng & Thanh toán (Cart & Orders)
- **Giỏ hàng (Cart)**: Thêm/Xóa/Tính tổng tiền vé cho từng session của khách hàng.
- **Thanh toán (Checkout)**: Mô phỏng các cổng thanh toán điện tử (VNPay, Momo, Banking). Hoàn tất quá trình checkout ngay lập tức, dọn sạch giỏ hàng.
- **Order Flow**: Lưu vết Lịch sử mua hàng (Order & OrderItems).

### 5. Check-in & Vé điện tử (E-Ticket)
- Tự động sinh `TicketCode` (Mã vé độc nhất) sau khi thanh toán thành công.
- Tự động sinh link **QR Code** nhúng vào vé để thuận tiện cho việc check-in.
- **Tính năng Check-in**: Ban tổ chức dán mã vé để check-in tại cổng, trạng thái đổi từ `VALID` sang `USED`. Tránh tình trạng tái sử dụng vé.


### Front-end: `npm run dev`
    `http://localhost:5173/`
<!-- Docker build & run 
docker build -t event-service:0.0.1 .
docker run --name event-service --network canhhocit-network -p 8080:8080 event-service:0.0.1 -->