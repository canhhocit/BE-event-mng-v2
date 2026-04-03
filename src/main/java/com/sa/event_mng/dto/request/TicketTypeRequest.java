package com.sa.event_mng.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TicketTypeRequest {
    @NotBlank(message = "TICKET_NAME_REQUIRED")
    private String name;

    private String description;

    @Min(value = 0, message = "TICKET_PRICE_INVALID")
    private BigDecimal price;

    @Min(value = 1, message = "TICKET_QUANTITY_INVALID")
    private Integer totalQuantity;

    private Long eventId;
}
