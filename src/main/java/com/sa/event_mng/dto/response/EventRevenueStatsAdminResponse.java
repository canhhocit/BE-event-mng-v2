package com.sa.event_mng.dto.response;

import lombok.*;

import java.math.BigDecimal;
import java.util.List;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EventRevenueStatsAdminResponse {
    private BigDecimal totalRevenue;
    private List<MonthlyRevenueResponse> monthlyRevenues;
}
