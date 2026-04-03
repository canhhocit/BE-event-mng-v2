package com.sa.event_mng.controller;

import com.sa.event_mng.dto.request.TicketTypeRequest;
import com.sa.event_mng.dto.response.ApiResponse;
import com.sa.event_mng.dto.response.TicketTypeResponse;
import com.sa.event_mng.service.TicketTypeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/ticket-types")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Loại vé", description = "Thiết lập và quản lý các loại vé cho sự kiện")
public class TicketTypeController {

    TicketTypeService ticketTypeService;

    @PostMapping
    @Operation(summary = "Tạo loại vé mới cho sự kiện (ORGANIZER/ADMIN)")
    public ApiResponse<TicketTypeResponse> create(@RequestBody @Valid TicketTypeRequest request) {
        return ApiResponse.<TicketTypeResponse>builder()
                .result(ticketTypeService.create(request))
                .build();
    }

    @GetMapping("/event/{eventId}")
    @Operation(summary = "Lấy danh sách loại vé theo sự kiện")
    public ApiResponse<List<TicketTypeResponse>> getByEvent(@PathVariable Long eventId) {
        return ApiResponse.<List<TicketTypeResponse>>builder()
                .result(ticketTypeService.getByEvent(eventId))
                .build();
    }
}
