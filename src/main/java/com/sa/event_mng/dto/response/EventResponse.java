package com.sa.event_mng.dto.response;

import com.sa.event_mng.model.enums.EventStatus;
import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventResponse {
    private Long id;
    private String name;
    private String categoryName;
    private String organizerName;
    private String location;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private LocalDateTime saleStartDate;
    private LocalDateTime saleEndDate;
    private String description;
    private EventStatus status;
    private List<String> imageUrls;
    private List<TicketTypeResponse> ticketTypes;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
