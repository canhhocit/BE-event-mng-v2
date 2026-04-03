package com.sa.event_mng.model.entity;

import com.sa.event_mng.model.enums.TicketStatus;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "tickets")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Ticket extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_id")
    private Order order;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ticket_type_id")
    private TicketType ticketType;

    @Column(name = "ticket_code", nullable = false, unique = true, length = 100)
    private String ticketCode;

    @Column(name = "qr_code")
    private String qrCode;

    @Enumerated(EnumType.STRING)
    private TicketStatus status;

    @Column(name = "used_at")
    private LocalDateTime usedAt;
}
