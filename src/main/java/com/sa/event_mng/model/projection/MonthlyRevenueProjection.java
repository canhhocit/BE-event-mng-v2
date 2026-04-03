package com.sa.event_mng.model.projection;

import java.math.BigDecimal;

public interface MonthlyRevenueProjection {
    int getYear();
    int getMonth();
    BigDecimal getRevenue();
}
