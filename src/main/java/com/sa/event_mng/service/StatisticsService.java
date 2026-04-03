package com.sa.event_mng.service;

import com.sa.event_mng.dto.response.*;
import com.sa.event_mng.mapper.StatsMapper;
import com.sa.event_mng.model.projection.*;
import com.sa.event_mng.repository.StatisticsRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class StatisticsService {

    StatisticsRepository statisticsRepository;
    StatsMapper statsMapper;

    @PreAuthorize("hasRole('ADMIN')")
    public EventStatusStatsResponse getEventStatusStats(Long quarter, Long year) {
        List<EventStatusStatsProjection> eventStatusStatsProjections = statisticsRepository.findEventStatusStats(quarter, year);
        long total = eventStatusStatsProjections.stream()
                .mapToLong(EventStatusStatsProjection::getCount)
                .sum();

        List<EventStatusStatsResponse.EventStatusStatsDetail> statusDetails = eventStatusStatsProjections.stream()
                .map(statsMapper::toEventStatusStatsDetail)
                .map(detail -> new EventStatusStatsResponse.EventStatusStatsDetail(
                        detail.getStatus(),
                        total == 0 ? 0.0 : (detail.getCountEvents() * 100.0) / total,
                        detail.getCountEvents()
                ))
                .toList();

        return EventStatusStatsResponse.builder()
                .quarter(quarter)
                .year(year)
                .total(total)
                .eventStatusStatsDetail(statusDetails)
                .build();
    }

    Map<Integer, String> dayOfWeekMap = Map.of(
            1, "Sunday",
            2, "Monday",
            3, "Tuesday",
            4, "Wednesday",
            5, "Thursday",
            6, "Friday",
            7, "Saturday"
    );

    @PreAuthorize("hasRole('ADMIN')")
    public EventTemporalStatsResponse getEventTemporalStats(int dayOfWeek) {

        List<EventTemporalStatsProjection> eventTemporalStatsProjection = statisticsRepository.findEventTemporalStats(dayOfWeek);

        List<EventTemporalStatsResponse.EventTemporalStatsDetail> eventTemporalStatsDetails = eventTemporalStatsProjection.stream()
                .map(statsMapper::toEventTemporalStatsResponse)
                .map(detail -> new EventTemporalStatsResponse.EventTemporalStatsDetail(
                        detail.getHourOfDay(),
                        detail.getCountEvents(),
                        detail.getTotalTickets(),
                        detail.getTicketsSold(),
                        detail.getPercentageOfTicketsSold()
                ))
                .toList();
        return EventTemporalStatsResponse.builder()
                .day(dayOfWeekMap.get(dayOfWeek))
                .eventTemporalStatsDetail(eventTemporalStatsDetails)
                .build();
    }

    @PreAuthorize("hasRole('ORGANIZER') and @securityCustom.isCurrentUser(#idOrganizer, authentication)")
    public List<EventRevenueStatsOrganizerResponse> getEventRevenueStatsOrganizer(Long idOrganizer) {
        List<EventRevenueStatsOrganizerProjection> eventRevenueStats = statisticsRepository.findEventRevenueOrganizerStats(idOrganizer);
        return eventRevenueStats.stream()
                .map(statsMapper::toEventRevenueStatsResponse)
                .toList();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public EventRevenueStatsAdminResponse getEventRevenueStatsAdmin() {
        EventRevenueStatsAdminProjection totalStats = statisticsRepository.findEventRevenueAdminStats();
        List<MonthlyRevenueProjection> dbMonthly = statisticsRepository.findMonthlyRevenueAdmin();
        
        List<MonthlyRevenueResponse> monthlyList = new ArrayList<>();
        LocalDate now = LocalDate.now();
        for (int i = 5; i >= 0; i--) {
            LocalDate date = now.minusMonths(i);
            int y = date.getYear();
            int m = date.getMonthValue();
            
            BigDecimal rev = dbMonthly.stream()
                .filter(p -> p.getYear() == y && p.getMonth() == m)
                .map(MonthlyRevenueProjection::getRevenue)
                .findFirst().orElse(BigDecimal.ZERO);
            
            monthlyList.add(MonthlyRevenueResponse.builder()
                            .year(y)
                            .month(m)
                            .revenue(rev)
                            .build());
        }

        return EventRevenueStatsAdminResponse.builder()
                .totalRevenue(totalStats != null ? totalStats.getTotalRevenue() : BigDecimal.ZERO)
                .monthlyRevenues(monthlyList)
                .build();
    }
}
