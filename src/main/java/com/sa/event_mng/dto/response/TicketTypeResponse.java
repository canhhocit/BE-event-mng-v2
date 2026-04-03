package com.sa.event_mng.dto.response;

import lombok.*;
import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TicketTypeResponse {
    private Long id;
    private String name;
    private BigDecimal price;
    private Integer totalQuantity;
    private Integer remainingQuantity;
    private String description;
}
