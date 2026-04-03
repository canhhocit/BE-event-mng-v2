package com.sa.event_mng.model.enums;

public enum EventStatus {
    PENDING,    // Chờ Admin duyệt
    UPCOMING,   // Đã duyệt, chờ đến ngày mở bán vé
    OPENING,    // Bdau mở bán vé
    CLOSED,     // KT bán vé, chờ ngày diễn ra
    COMPLETED,  // Sự kiện đã kết thúc
    CANCELLED   // Bị Admin từ chối hoặc bị hủy
}
