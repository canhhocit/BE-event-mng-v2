package com.sa.event_mng.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
public class ResetPasswordRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Email is invalid")
    String email;

    @NotBlank(message = "OTP is required")
    String otp;

    @NotBlank(message = "Password must be not blank")
    @Size(min = 6, message = "Password must be at least 6 characters")
    String newPassword;
}
