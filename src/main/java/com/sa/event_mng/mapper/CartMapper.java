package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.CartItemResponse;
import com.sa.event_mng.dto.response.CartResponse;
import com.sa.event_mng.model.entity.Cart;
import com.sa.event_mng.model.entity.CartItem;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CartMapper {

    @Mapping(target = "totalAmount", expression = "java(calculateTotal(cart.getItems()))")
    @Mapping(target = "items", source = "items", qualifiedByName = "mapCartItems")
    CartResponse toCartResponse(Cart cart);

    @Named("mapCartItems")
    default List<CartItemResponse> mapCartItems(List<CartItem> items) {
        if (items == null) {
            return new ArrayList<>();
        }
        return items.stream()
                .map(this::toCartItemResponse)
                .collect(Collectors.toList());
    }

    @Mapping(target = "ticketTypeId", source = "ticketType.id")
    @Mapping(target = "ticketTypeName", source = "ticketType.name")
    @Mapping(target = "eventName", source = "ticketType.event.name")
    CartItemResponse toCartItemResponse(CartItem cartItem);

    default BigDecimal calculateTotal(List<CartItem> items) {
        if (items == null || items.isEmpty()) {
            return BigDecimal.ZERO;
        }
        return items.stream()
                .map(CartItem::getSubtotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }
}
