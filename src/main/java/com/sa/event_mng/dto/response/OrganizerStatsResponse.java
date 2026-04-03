package com.sa.event_mng.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrganizerStatsResponse {
    private long totalEvents;
    private long totalTicketsSold;
    private double totalRevenue;
    private List<EventStat> eventStats;
    private List<MonthlyRevenue> monthlyRevenues;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class EventStat {
        private Long eventId;
        private String eventName;
        private long totalTickets;
        private long ticketsSold;
        private double revenue;
        private double sellThroughRate; // Percentage
        private String status;
        private String imageUrl;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class MonthlyRevenue {
        private int year;
        private int month;
        private java.math.BigDecimal revenue;
    }
}
