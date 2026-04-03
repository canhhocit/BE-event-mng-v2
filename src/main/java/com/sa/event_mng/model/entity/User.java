package com.sa.event_mng.model.entity;

import com.sa.event_mng.model.enums.Role;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(callSuper = true)
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = true)
    private String email;

    @Column(nullable = false)
    private String password;

    private String fullName;

    private String phone;

    private String address;

    @Enumerated(EnumType.STRING)
    private Role role;

    private boolean enabled;

    private String verificationToken;

}
