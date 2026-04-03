package com.sa.event_mng.dto.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
//Thống kê theo thời gian
public class EventTemporalStatsResponse {
    private String day;
    private List<EventTemporalStatsDetail> eventTemporalStatsDetail;

    @Data
    @AllArgsConstructor
    public static class EventTemporalStatsDetail {
        private Integer hourOfDay;
        private Long countEvents;
        private Long totalTickets;
        private Long ticketsSold;
        private Double percentageOfTicketsSold;
    }
}
