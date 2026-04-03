package com.sa.event_mng.model.entity;

import com.sa.event_mng.model.enums.OrderStatus;
import com.sa.event_mng.model.enums.PaymentMethod;
import com.sa.event_mng.model.enums.PaymentStatus;
import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "orders")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Order extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "customer_id")
    private User customer;

    @Column(name = "organizer_amount", nullable = false, precision = 12, scale = 2)
    private BigDecimal organizerAmount; // tổng tiền btc ăn

    @Column(name="platform_fee_rate", nullable = false)
    private Float platformFeeRate;  //phần trăm tiền admin ăn

    @Column(name = "service_fee", nullable = false, precision = 12, scale = 2)
    private BigDecimal serviceFee;  //tổng tiền admin ăn

    @Column(name = "total_amount", nullable = false, precision = 12, scale = 2)
    private BigDecimal totalAmount; //tổng tiền khách phải trả

    @Enumerated(EnumType.STRING)
    @Column(name = "payment_method")
    private PaymentMethod paymentMethod;

    @Enumerated(EnumType.STRING)
    @Column(name = "payment_status")
    private PaymentStatus paymentStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "order_status")
    private OrderStatus orderStatus;

    @Column(name = "order_date")
    private LocalDateTime orderDate;

    @Column(name = "paid_at")
    private LocalDateTime paidAt;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<OrderItem> items;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Ticket> tickets;
}
