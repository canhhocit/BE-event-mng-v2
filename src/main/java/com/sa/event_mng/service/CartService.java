package com.sa.event_mng.service;

import com.sa.event_mng.dto.request.CartItemRequest;
import com.sa.event_mng.dto.response.CartResponse;
import com.sa.event_mng.exception.AppException;
import com.sa.event_mng.exception.ErrorCode;
import com.sa.event_mng.mapper.CartMapper;
import com.sa.event_mng.model.entity.*;
import com.sa.event_mng.model.enums.CartStatus;
import com.sa.event_mng.repository.*;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class CartService {

    CartRepository cartRepository;
    UserRepository userRepository;
    TicketTypeRepository ticketTypeRepository;
    CartMapper cartMapper;

    @Transactional
    public CartResponse addToCart(CartItemRequest request) {
        User user = getCurrentUser();
        log.info("Adding to cart: User={}, TicketType={}, Quantity={}", 
                user.getUsername(), request.getTicketTypeId(), request.getQuantity());

        if (request.getQuantity() == null || request.getQuantity() <= 0) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        Cart cart = cartRepository.findByCustomerId(user.getId())
                .orElseGet(() -> cartRepository.save(Cart.builder()
                        .customer(user)
                        .status(CartStatus.ACTIVE)
                        .items(new ArrayList<>())
                        .build()));

        TicketType ticketType = ticketTypeRepository.findById(request.getTicketTypeId())
                .orElseThrow(() -> new AppException(ErrorCode.TICKET_TYPE_NOT_FOUND));

        // check event status
        if (ticketType.getEvent().getStatus() != com.sa.event_mng.model.enums.EventStatus.OPENING) {
            log.warn("Event is not OPENING: EventId={}", ticketType.getEvent().getId());
            throw new AppException(ErrorCode.EVENT_NOT_OPENING);
        }

        // check stock
        Optional<CartItem> existingItem = cart.getItems().stream()
                .filter(item -> item.getTicketType().getId().equals(request.getTicketTypeId()))
                .findFirst();

        int currentInCart = existingItem.map(CartItem::getQuantity).orElse(0);
        int totalQuantityRequested = currentInCart + request.getQuantity();

        log.info("Stock check: Remaining={}, InCart={}, RequestedNew={}, TotalRequested={}", 
                ticketType.getRemainingQuantity(), currentInCart, request.getQuantity(), totalQuantityRequested);

        if (totalQuantityRequested > ticketType.getRemainingQuantity()) {
            log.error("Not enough tickets: Stock={}, Requested={}", 
                    ticketType.getRemainingQuantity(), totalQuantityRequested);
            throw new AppException(ErrorCode.TICKET_NOT_ENOUGH);
        }

        // ins or update
        if (existingItem.isPresent()) {
            CartItem item = existingItem.get();
            item.setQuantity(totalQuantityRequested);
            item.setSubtotal(item.getUnitPrice().multiply(BigDecimal.valueOf(item.getQuantity())));
        } else {
            CartItem newItem = CartItem.builder()
                    .cart(cart)
                    .ticketType(ticketType)
                    .quantity(request.getQuantity())
                    .unitPrice(ticketType.getPrice())
                    .subtotal(ticketType.getPrice().multiply(BigDecimal.valueOf(request.getQuantity())))
                    .build();
            cart.getItems().add(newItem);
        }

        return cartMapper.toCartResponse(cartRepository.save(cart));
    }

    public CartResponse getMyCart() {
        User user = getCurrentUser();
        Cart cart = cartRepository.findByCustomerId(user.getId())
                .orElseGet(() -> Cart.builder().items(new ArrayList<>()).build());
        return cartMapper.toCartResponse(cart);
    }

    @Transactional
    public CartResponse updateQuantity(Long itemId, Integer quantity) {
        if (quantity == null || quantity <= 0) {
            return removeItem(itemId);
        }

        User user = getCurrentUser();
        Cart cart = cartRepository.findByCustomerId(user.getId())
                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

        CartItem item = cart.getItems().stream()
                .filter(i -> i.getId().equals(itemId))
                .findFirst()
                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

        TicketType tt = item.getTicketType();
        if (quantity > tt.getRemainingQuantity()) {
            throw new AppException(ErrorCode.TICKET_NOT_ENOUGH);
        }

        item.setQuantity(quantity);
        item.setSubtotal(item.getUnitPrice().multiply(BigDecimal.valueOf(quantity)));

        return cartMapper.toCartResponse(cartRepository.save(cart));
    }

    @Transactional
    public CartResponse removeItem(Long itemId) {
        User user = getCurrentUser();
        Cart cart = cartRepository.findByCustomerId(user.getId())
                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

        cart.getItems().removeIf(item -> item.getId().equals(itemId));

        return cartMapper.toCartResponse(cartRepository.save(cart));
    }

    @Transactional
    public void clearCart() {
        User user = getCurrentUser();
        cartRepository.findByCustomerId(user.getId()).ifPresent(cart -> {
            cart.getItems().clear();
            cartRepository.save(cart);
        });
    }

    private User getCurrentUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
    }

}
