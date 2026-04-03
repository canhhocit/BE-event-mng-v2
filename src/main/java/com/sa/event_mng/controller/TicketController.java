package com.sa.event_mng.controller;

import com.sa.event_mng.dto.response.ApiResponse;
import com.sa.event_mng.dto.response.TicketResponse;
import com.sa.event_mng.service.TicketService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tickets")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Vé điện tử", description = "Xem vé và thực hiện check-in")
public class TicketController {

    TicketService ticketService;

    @GetMapping("/my-tickets")
    @Operation(summary = "Xem danh sách vé đã mua")
    public ApiResponse<List<TicketResponse>> getMyTickets() {
        return ApiResponse.<List<TicketResponse>>builder()
                .result(ticketService.getMyTickets())
                .build();
    }

    @PostMapping("/check-in")
    @Operation(summary = "Quét mã vé để check-in (Chỉ Ban tổ chức/Admin)")
    public ApiResponse<TicketResponse> checkIn(@RequestParam String ticketCode) {
        return ApiResponse.<TicketResponse>builder()
                .result(ticketService.checkIn(ticketCode))
                .build();
    }
}
