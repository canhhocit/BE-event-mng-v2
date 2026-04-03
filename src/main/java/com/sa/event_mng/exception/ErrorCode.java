package com.sa.event_mng.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import lombok.Getter;

@Getter
public enum ErrorCode {
    // General errors
    KEY_INVALID(1001, "Uncategorize error", HttpStatus.BAD_REQUEST),
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorize exception", HttpStatus.INTERNAL_SERVER_ERROR),

    // User errors (1002-1099)
    USER_EXISTED(1002, "User existed", HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(1003, "User not existed", HttpStatus.NOT_FOUND),

    USERNAME_INVALID(1004, "Username must be at least 3 characters", HttpStatus.BAD_REQUEST),
    PASSWORD_INVALID(1005, "Password must be at least 6 characters", HttpStatus.BAD_REQUEST),

    USERNAME_REQUIRED(1006, "Username is required", HttpStatus.BAD_REQUEST),
    USERNAME_EXISTED(1021, "Username already existed", HttpStatus.BAD_REQUEST),
    PASSWORD_REQUIRED(1007, "Password is required", HttpStatus.BAD_REQUEST),

    EMAIL_REQUIRED(1008, "Email is required", HttpStatus.BAD_REQUEST),
    EMAIL_INVALID(1009, "Email format is invalid", HttpStatus.BAD_REQUEST),
    EMAIL_EXISTED(1010, "Email already existed", HttpStatus.BAD_REQUEST),
    ACCOUNT_NOT_VERIFIED(1022, "The email has already been sent. Please check your inbox again.", HttpStatus.CONFLICT),

    FULLNAME_REQUIRED(1011, "Full name is required", HttpStatus.BAD_REQUEST),
    FULLNAME_TOO_LONG(1012, "Full name is too long", HttpStatus.BAD_REQUEST),

    PHONE_INVALID(1013, "Phone number is invalid", HttpStatus.BAD_REQUEST),

    ADDRESS_TOO_LONG(1014, "Address is too long", HttpStatus.BAD_REQUEST),

    PASSWORD_WEAK(1015, "Password must contain at least one uppercase letter and one number", HttpStatus.BAD_REQUEST),

    USER_DISABLED(1016, "Tài khoản của bạn đã bị vô hiệu hóa.", HttpStatus.FORBIDDEN),
    USER_UNAUTHORIZED(1017, "Unauthorized access", HttpStatus.UNAUTHORIZED),

    PASSWORD_NOT_MATCH(1018, "Password does not match", HttpStatus.BAD_REQUEST),

    // Authentication & Authorization (4006-4007)
    UNAUTHENTICATED(4006, "Unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(4007, "You do not have permission", HttpStatus.FORBIDDEN),

    // Category errors (2001-2099)
    CATEGORY_NOT_FOUND(2001, "Category not found", HttpStatus.NOT_FOUND),
    CATEGORY_EXISTED(2002, "Category already existed", HttpStatus.BAD_REQUEST),
    CATEGORY_NAME_REQUIRED(2003, "Category name is required", HttpStatus.BAD_REQUEST),
    CATEGORY_NAME_INVALID(2004, "Category name must be at least 5 characters", HttpStatus.BAD_REQUEST),
    CATEGORY_ID_REQUIRED(2005, "Category ID is required", HttpStatus.BAD_REQUEST),

    // Event errors (3001-3099)
    EVENT_NOT_FOUND(3001, "Event not found", HttpStatus.NOT_FOUND),

    // FILE
    FILE_INPUT_ERR(4001, "Cannot store file", HttpStatus.BAD_REQUEST),
    FILE_EMPTY(4002, "File is empty", HttpStatus.BAD_REQUEST),
    INVALID_TOKEN(1020, "Invalid token", HttpStatus.BAD_REQUEST),

    // Cart & Order
    CART_EMPTY(5001, "Your cart is empty", HttpStatus.BAD_REQUEST),
    TICKET_TYPE_NOT_FOUND(5002, "Ticket type not found", HttpStatus.NOT_FOUND),
    EVENT_NOT_OPENING(5003, "Event is not opening for sale", HttpStatus.BAD_REQUEST),
    TICKET_NOT_ENOUGH(5004, "Not enough tickets available", HttpStatus.BAD_REQUEST),
    ORDER_NOT_FOUND(6001, "Order not found", HttpStatus.NOT_FOUND),
    
    // TicketType validation (7001-7099)
    TICKET_NAME_REQUIRED(7001, "Tên hạng vé không được để trống", HttpStatus.BAD_REQUEST),
    TICKET_PRICE_INVALID(7002, "Giá vé phải lớn hơn hoặc bằng 0", HttpStatus.BAD_REQUEST),
    TICKET_QUANTITY_INVALID(7003, "Số lượng vé phải lớn hơn 0", HttpStatus.BAD_REQUEST),
    TICKET_INVALID(7004, "Mã vé không hợp lệ", HttpStatus.BAD_REQUEST),
    TICKET_USED(7005, "Vé này đã được sử dụng trước đó", HttpStatus.BAD_REQUEST),
    TICKET_NOT_OWNED(7006, "Bạn không có quyền quét vé của sự kiện này", HttpStatus.FORBIDDEN);

    private int code;
    private String message;
    private HttpStatusCode statusCode;

    ErrorCode(int code, String message, HttpStatusCode statusCode) {
        this.code = code;
        this.message = message;
        this.statusCode = statusCode;
    }
}