package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Order;
import com.sa.event_mng.model.entity.OrderItem;
import com.sa.event_mng.model.entity.TicketType;
import com.sa.event_mng.repository.OrderRepository;
import com.sa.event_mng.repository.TicketTypeRepository;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class OrderItemSeeder {

    private final OrderRepository orderRepository;
    private final TicketTypeRepository ticketTypeRepository;
    private final Random random = new Random();

    public OrderItemSeeder(OrderRepository orderRepository, TicketTypeRepository ticketTypeRepository) {
        this.orderRepository = orderRepository;
        this.ticketTypeRepository = ticketTypeRepository;
    }

    public void seed() {
        List<Order> orders = orderRepository.findAll();
        List<TicketType> ticketTypes = ticketTypeRepository.findAll();

        if (orders.isEmpty()) {
            System.out.println("No orders found. Seed orders first.");
            return;
        }

        if (ticketTypes.isEmpty()) {
            System.out.println("No ticket types found. Seed ticket types first.");
            return;
        }

        int createdCount = 0;

        for (Order order : orders) {
            if (order.getItems() != null && !order.getItems().isEmpty()) {
                continue;
            }

            int itemCount = random.nextInt(3) + 1;
            List<OrderItem> items = new ArrayList<>();
            BigDecimal totalAmount = BigDecimal.ZERO;

            for (int i = 0; i < itemCount; i++) {
                TicketType ticketType = ticketTypes.get(random.nextInt(ticketTypes.size()));

                if (ticketType.getRemainingQuantity() == null || ticketType.getRemainingQuantity() <= 0) {
                    continue;
                }

                int quantity = Math.min(random.nextInt(4) + 1, ticketType.getRemainingQuantity());
                BigDecimal unitPrice = ticketType.getPrice();
                BigDecimal subtotal = unitPrice.multiply(BigDecimal.valueOf(quantity));

                OrderItem item = new OrderItem();
                item.setOrder(order);
                item.setTicketType(ticketType);
                item.setQuantity(quantity);
                item.setUnitPrice(unitPrice);
                item.setSubtotal(subtotal);

                items.add(item);
                totalAmount = totalAmount.add(subtotal);
                createdCount++;
            }

            order.setItems(items);
            if (!items.isEmpty()) {
                order.setTotalAmount(totalAmount);
            }
        }

        orderRepository.saveAll(orders);
        System.out.println("Seeded " + createdCount + " order items");
    }
}