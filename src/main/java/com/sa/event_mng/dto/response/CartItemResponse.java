package com.sa.event_mng.dto.response;

import lombok.*;
import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CartItemResponse {
    private Long id;
    private Long ticketTypeId;
    private String ticketTypeName;
    private String eventName;
    private Integer quantity;
    private BigDecimal unitPrice;
    private BigDecimal subtotal;
}
