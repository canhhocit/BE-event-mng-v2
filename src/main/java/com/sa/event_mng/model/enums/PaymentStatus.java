package com.sa.event_mng.model.enums;

public enum PaymentStatus {
    PENDING, //chờ thanh toán
    PAID, //thanh toán thành công
    FAILED, //thanh toán thành công hoặc bị hủy
    REFUNDED //hoàn tiền
}
