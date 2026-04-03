package com.sa.event_mng.model.projection;

import java.math.BigDecimal;

public interface EventRevenueStatsOrganizerProjection {
    String getEventName();
    BigDecimal getTotalRevenue();
    Integer getTicketsSold();
    Double getPercentageOfTicketsSold();
}
