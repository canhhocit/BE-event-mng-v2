package com.sa.event_mng.dto.response;


import com.sa.event_mng.model.enums.Role;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
    Long id;

    String username;

    String email;

    String fullName;

    // String password;

    String phone;

    String address;

    boolean enabled;

    Role role;
}
