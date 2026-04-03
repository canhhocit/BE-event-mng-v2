package com.sa.event_mng.dto.response;

import com.sa.event_mng.model.enums.TicketStatus;
import lombok.*;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TicketResponse {
    private Long id;
    private String eventName;
    private String ticketTypeName;
    private String ticketCode;
    private String qrCode;
    private TicketStatus status;
    private LocalDateTime usedAt;
}
