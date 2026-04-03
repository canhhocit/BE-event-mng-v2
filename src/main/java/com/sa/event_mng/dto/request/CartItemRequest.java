package com.sa.event_mng.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CartItemRequest {
    @NotNull(message = "UNCATEGORIZED_EXCEPTION")
    private Long ticketTypeId;

    @Min(value = 1, message = "UNCATEGORIZED_EXCEPTION")
    private Integer quantity;
}
