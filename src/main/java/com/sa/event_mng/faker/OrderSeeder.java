package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Order;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.OrderStatus;
import com.sa.event_mng.model.enums.PaymentMethod;
import com.sa.event_mng.model.enums.PaymentStatus;
import com.sa.event_mng.model.enums.Role;
import com.sa.event_mng.repository.OrderRepository;
import com.sa.event_mng.repository.UserRepository;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class OrderSeeder {
    private final OrderRepository orderRepository;
    private final UserRepository userRepository;
    private final Random random = new Random();

    public OrderSeeder(OrderRepository orderRepository, UserRepository userRepository) {
        this.orderRepository = orderRepository;
        this.userRepository = userRepository;
    }

    public void seed() {
        if (orderRepository.count() > 0) return;

        List<User> users = userRepository.findByRole(Role.CUSTOMER);
        if (users.isEmpty()) {
            System.out.println("No users found. Seed users first.");
            return;
        }

        List<Order> orders = new ArrayList<>();

        for (int i = 0; i < 1000; i++) {
            User customer = users.get(random.nextInt(users.size()));

            LocalDateTime orderDate = LocalDateTime.now()
                    .minusDays(random.nextInt(30))
                    .minusHours(random.nextInt(24));

            PaymentMethod paymentMethod = randomPaymentMethod();
            OrderStatus orderStatus = randomOrderStatus();
            PaymentStatus paymentStatus = randomPaymentStatus(orderStatus);

            BigDecimal organizerAmount = randomAmount();
            float platformFeeRate = 0.25f;
            BigDecimal serviceFee = organizerAmount.multiply(BigDecimal.valueOf(platformFeeRate))
                    .setScale(2, BigDecimal.ROUND_HALF_UP);
            BigDecimal totalAmount = organizerAmount.add(serviceFee);

            Order order = new Order();
            order.setCustomer(customer);
            order.setOrganizerAmount(organizerAmount);
            order.setPlatformFeeRate(platformFeeRate);
            order.setServiceFee(serviceFee);
            order.setTotalAmount(totalAmount);
            order.setPaymentMethod(paymentMethod);
            order.setPaymentStatus(paymentStatus);
            order.setOrderStatus(orderStatus);
            order.setOrderDate(orderDate);
            order.setPaidAt(paymentStatus == PaymentStatus.PAID
                    ? orderDate.plusMinutes(random.nextInt(120) + 1)
                    : null);

            orders.add(order);
        }

        orderRepository.saveAll(orders);
        System.out.println("Seeded " + orders.size() + " orders");
    }

    @SuppressWarnings("deprecation")
    private BigDecimal randomAmount() {
        double value = 50000 + (5000000 - 50000) * random.nextDouble();
        return BigDecimal.valueOf(value).setScale(2, BigDecimal.ROUND_HALF_UP);
    }

    private PaymentMethod randomPaymentMethod() {
        PaymentMethod[] methods = PaymentMethod.values();
        return methods[random.nextInt(methods.length)];
    }

    private OrderStatus randomOrderStatus() {
        OrderStatus[] statuses = OrderStatus.values();
        return statuses[random.nextInt(statuses.length)];
    }

    private PaymentStatus randomPaymentStatus(OrderStatus orderStatus) {

        if (orderStatus == OrderStatus.CANCELLED) {
            PaymentStatus[] statuses = {PaymentStatus.FAILED, PaymentStatus.REFUNDED};
            return statuses[random.nextInt(statuses.length)];
        }
        if (orderStatus == OrderStatus.PENDING) {
            PaymentStatus[] statuses = {PaymentStatus.FAILED, PaymentStatus.PENDING};
            return statuses[random.nextInt(statuses.length)];
        }
        else { //OrderStatus.Comfirmed
            return PaymentStatus.PAID;
        }
    }
}

