package com.sa.event_mng.controller;

import com.sa.event_mng.dto.response.*;
import com.sa.event_mng.service.StatisticsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Thống kê", description = "Quản lý dữ liệu tổng hợp")
@SecurityRequirement(name = "bearerAuth")
public class StatisticsController {

    StatisticsService statisticsService;

    @GetMapping("/statistics-event/by-status/{quarter}/{year}")
    @Operation(summary = "Tỉ lệ phân bổ trạng thái từng quý (Admin)")
    public ApiResponse<EventStatusStatsResponse> getStatisticsByStatus(@PathVariable Long quarter, @PathVariable Long year) {
        return ApiResponse.<EventStatusStatsResponse>builder().result(statisticsService.getEventStatusStats(quarter, year)).build();
    }

    @GetMapping("/statistics-event/by-temporal/{dayOfWeek}")
    //            1, "Sunday",
    //            2, "Monday",
    //            3, "Tuesday",
    //            4, "Wednesday",
    //            5, "Thursday",
    //            6, "Friday",
    //            7, "Saturday"
    @Operation(summary = "Thống kê số lượng sự kiện bắt đầu (start_time) theo từng ngày trong tuần hoặc giờ trong ngày để tìm giờ vàng (Admin)")
    public ApiResponse<EventTemporalStatsResponse> getStatisticsByTemporal(@PathVariable int dayOfWeek) {
        return ApiResponse.<EventTemporalStatsResponse>builder().result(statisticsService.getEventTemporalStats(dayOfWeek)).build();
    }

    @GetMapping("/statistics-revenue/{id_organizer}")
    @Operation(summary = "Thống kê doanh thu (chủ sử kiện)")
    public ApiResponse<List<EventRevenueStatsOrganizerResponse>> getStatisticsRevenueOrganizer(@PathVariable("id_organizer") Long idOrganizer) {
        return ApiResponse.<List<EventRevenueStatsOrganizerResponse>>builder().result(statisticsService.getEventRevenueStatsOrganizer(idOrganizer)).build();
    }

    @GetMapping("/statistics-revenue/admin")
    @Operation(summary = "Thống kê doanh thu (admin, tính tổng tiền dịch vụ)")
    public ApiResponse<EventRevenueStatsAdminResponse> getStatisticsRevenueAdmin() {
        return ApiResponse.<EventRevenueStatsAdminResponse>builder().result(statisticsService.getEventRevenueStatsAdmin()).build();
    }
}