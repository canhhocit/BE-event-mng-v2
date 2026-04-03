package com.sa.event_mng.controller;

import com.sa.event_mng.dto.response.ApiResponse;
import com.sa.event_mng.dto.response.OrderResponse;
import com.sa.event_mng.model.enums.PaymentMethod;
import com.sa.event_mng.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Đơn hàng", description = "Thanh toán và xem lịch sử mua vé")
public class OrderController {

    OrderService orderService;

    @PostMapping("/checkout")
    @Operation(summary = "Thanh toán toàn bộ giỏ hàng")
    public ApiResponse<OrderResponse> checkout(@RequestParam PaymentMethod paymentMethod) {
        return ApiResponse.<OrderResponse>builder()
                .result(orderService.checkout(paymentMethod))
                .build();
    }

    @PostMapping("/checkout-selected")
    @Operation(summary = "Thanh toán các mục được chọn trong giỏ hàng")
    public ApiResponse<OrderResponse> checkoutSelected(@RequestBody java.util.List<Long> itemIds, @RequestParam PaymentMethod paymentMethod) {
        return ApiResponse.<OrderResponse>builder()
                .result(orderService.checkoutSelected(itemIds, paymentMethod))
                .build();
    }

    @GetMapping
    @Operation(summary = "Xem lịch sử đơn hàng của tôi")
    public ApiResponse<Page<OrderResponse>> getMyOrders(@RequestParam(defaultValue = "1") int page,
                                                        @RequestParam(defaultValue = "10") int size) {
        PageRequest pageRequest = PageRequest.of(
                page - 1, size,
                Sort.by("createdAt").descending());
        return ApiResponse.<Page<OrderResponse>>builder()
                .result(orderService.getMyOrders(pageRequest))
                .build();
    }
}
