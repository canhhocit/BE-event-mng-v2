# Postman API Testing Guide & JSON Data

Sử dụng tài liệu này để kiểm thử hệ thống qua Postman. Tất cả các API trả về định dạng `ApiResponse`.

**Base URL tổng quát:** `http://localhost:8080/event-mng`

**Swagger UI:** [http://localhost:8080/event-mng/swagger-ui/index.html](http://localhost:8080/event-mng/swagger-ui/index.html)
**API Docs:** [http://localhost:8080/event-mng/v3/api-docs](http://localhost:8080/event-mng/v3/api-docs)

---

## 1. Xác thực (Authentication)
**Path:** `/auth`

### 📝 Đăng ký tài khoản
- **Method:** `POST /register`
- **Full URL:** `http://localhost:8080/event-mng/auth/register`
- **Body:**
```json
{
  "username": "customer01",
  "password": "password123",
  "email": "customer01@example.com",
  "fullName": "Nguyễn Văn A",
  "phone": "97574417040",
  "address": "string"
}
```

### 🏢 Đăng ký tài khoản Ban tổ chức (Organizer)
- **Method:** `POST /register`
- **Body:**
```json
{
  "username": "organizer01",
  "password": "password123",
  "email": "organizer01@example.com",
  "fullName": "Công ty Sự kiện X",
  "phone": "97574417040",
  "address": "string",
  "role": "ORGANIZER"
}
```

### 🔑 Đăng nhập
- **Method:** `POST /login`
- **Full URL:** `http://localhost:8080/event-mng/auth/login`
- **Body:**
```json
{
  "username": "customer01",
  "password": "password123"
}
```
*Lưu ý: Copy `token` từ kết quả để dùng cho các API sau (phần Bearer Token).*

---

## 2. Quản lý Sự kiện (Organizer/Admin)

### 📁 Tạo Danh mục
- **Method:** `POST /categories`
- **Full URL:** `http://localhost:8080/event-mng/categories`
- **Body:**
```json
{
  "name": "Âm nhạc",
  "description": "Các buổi liveshow và concert"
}
```

### 📅 Tạo Sự kiện mới
- **Method:** `POST /events`
- **Full URL:** `http://localhost:8080/event-mng/events`
- **Body Type:** `form-data`
- **Fields:**
  - `name`: "Concert Chillies - Trên Những Đám Mây" *(Text)*
  - `categoryId`: 1 *(Text)*
  - `location`: "Nhà thi đấu Phú Thọ, TP.HCM" *(Text)*
  - `startTime`: "2026-05-20T19:00:00" *(Text)*
  - `endTime`: "2026-05-20T22:00:00" *(Text)*
  - `description`: "Show diễn cá nhân lớn nhất năm của Chillies." *(Text)*
  - `status`: "PUBLISHED" *(Text)*
  - `files`: [Chọn file ảnh từ máy tính] *(File)* Có thể chọn nhiều file.

### 🎫 Thiết lập Loại vé
- **Method:** `POST /ticket-types`
- **Full URL:** `http://localhost:8080/event-mng/ticket-types`
- **Body:**
```json
{
  "eventId": 1,
  "name": "Vé VIP (Fanzone)",
  "price": 1500000,
  "totalQuantity": 500,
  "description": "Gần sân khấu, kèm quà tặng."
}
```

---

## 3. Mua vé (Customer)

### 🛒 Thêm vào giỏ hàng
- **Method:** `POST /cart/add`
- **Full URL:** `http://localhost:8080/event-mng/cart/add`
- **Body:**
```json
{
  "ticketTypeId": 1,
  "quantity": 2
}
```

### 💳 Thanh toán (Checkout)
- **Method:** `POST /orders/checkout?paymentMethod=VNPAY`
- **Full URL:** `http://localhost:8080/event-mng/orders/checkout?paymentMethod=VNPAY`
*Lưu ý: Query parameter `paymentMethod` có các giá trị: MOMO, VNPAY, BANKING.*

---

## 4. Kiểm tra & Check-in

### 🎟️ Xem vé đã mua
- **Method:** `GET /tickets/my-tickets`
- **Full URL:** `http://localhost:8080/event-mng/tickets/my-tickets`

### ✅ Check-in (Ban tổ chức)
- **Method:** `POST /tickets/check-in?ticketCode=TKT-XXXXXXX`
- **Full URL:** `http://localhost:8080/event-mng/tickets/check-in?ticketCode=TKT-XXXXXXX`

---
### 💡 Mẹo Postman:
1. Tạo một **Environment** trong Postman.
2. Lưu token vào biến `jwt_token`.
3. Trong tab **Authorization** của các request, chọn `Bearer Token` và nhập `{{jwt_token}}`.
