package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Order;
import com.sa.event_mng.model.entity.OrderItem;
import com.sa.event_mng.model.entity.Ticket;
import com.sa.event_mng.model.enums.EventStatus;
import com.sa.event_mng.model.enums.OrderStatus;
import com.sa.event_mng.model.enums.PaymentStatus;
import com.sa.event_mng.model.enums.TicketStatus;
import com.sa.event_mng.repository.OrderRepository;
import com.sa.event_mng.repository.TicketRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

@Component
public class TicketSeeder {

    private final TicketRepository ticketRepository;
    private final OrderRepository orderRepository;
    private final Random random = new Random();

    public TicketSeeder(TicketRepository ticketRepository, OrderRepository orderRepository) {
        this.ticketRepository = ticketRepository;
        this.orderRepository = orderRepository;
    }

    public void seed() {
        if (ticketRepository.count() > 0) return;

        List<Order> orders = orderRepository.findAll();
        if (orders.isEmpty()) {
            System.out.println("No orders found. Seed orders first.");
            return;
        }

        List<Ticket> tickets = new ArrayList<>();

        for (Order order : orders) {
            if (order.getItems() == null || order.getItems().isEmpty()) {
                continue;
            }

            if (order.getPaymentStatus() != PaymentStatus.PAID) {
                continue;
            }

            for (OrderItem item : order.getItems()) {
                for (int i = 0; i < item.getQuantity(); i++) {
                    TicketStatus status = determineTicketStatus(order, item);

                    Ticket ticket = new Ticket();
                    ticket.setOrder(order);
                    ticket.setTicketType(item.getTicketType());
                    ticket.setTicketCode(generateTicketCode());
                    ticket.setQrCode("QR-" + UUID.randomUUID());
                    ticket.setStatus(status);
                    ticket.setUsedAt(resolveUsedAt(status, item));

                    tickets.add(ticket);
                }
            }
        }

        ticketRepository.saveAll(tickets);
        System.out.println("Seeded " + tickets.size() + " tickets");
    }

    private String generateTicketCode() {
        return "TICKET-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private TicketStatus determineTicketStatus(Order order, OrderItem item) {
        if (item.getTicketType() == null || item.getTicketType().getEvent() == null) {
            return TicketStatus.VALID;
        }

        if (item.getTicketType().getEvent().getStatus() == EventStatus.CANCELLED) {
            return TicketStatus.CANCELLED;
        }

        if (order.getOrderStatus() == OrderStatus.CANCELLED) {
            return TicketStatus.REFUNDED;
        }

        LocalDateTime startTime = item.getTicketType().getEvent().getStartTime();
        if (startTime == null) {
            return TicketStatus.VALID;
        }

        Duration duration = Duration.between(LocalDateTime.now(), startTime);

        if (duration.toHours() > 24) {
            return TicketStatus.VALID;
        }

        return random.nextBoolean() ? TicketStatus.USED : TicketStatus.VALID;
    }

    private LocalDateTime resolveUsedAt(TicketStatus status, OrderItem item) {
        if (status != TicketStatus.USED) {
            return null;
        }

        if (item.getTicketType() == null || item.getTicketType().getEvent() == null) {
            return LocalDateTime.now();
        }

        LocalDateTime startTime = item.getTicketType().getEvent().getStartTime();
        if (startTime == null) {
            return LocalDateTime.now();
        }

        return startTime.minusHours(1);
    }
}