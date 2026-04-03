package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.OrderResponse;
import com.sa.event_mng.model.entity.Order;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface OrderMapper {
    OrderResponse toOrderResponse(Order order);
}
