package com.sa.event_mng.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import java.text.ParseException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.sa.event_mng.dto.request.AuthenticationRequest;
import com.sa.event_mng.dto.request.IntrospectRequest;
import com.sa.event_mng.dto.request.LogoutRequest;
import com.sa.event_mng.dto.request.RefreshRequest;
import com.sa.event_mng.dto.request.UserCreateRequest;
import com.sa.event_mng.dto.response.AuthenticationResponse;
import com.sa.event_mng.dto.response.IntrospectResponse;
import com.sa.event_mng.exception.AppException;
import com.sa.event_mng.exception.ErrorCode;
import com.sa.event_mng.model.entity.InvalidatedToken;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.Role;
import com.sa.event_mng.repository.InvalidatedTokenRepository;
import com.sa.event_mng.repository.UserRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class AuthenticationService {

    UserRepository userRepository;
    PasswordEncoder passwordEncoder;
    EmailService emailService;
    InvalidatedTokenRepository invalidatedTokenRepository;

    @NonFinal
    @Value("${application.security.jwt.secret-key}")
    protected String SIGNER_KEY;

    @NonFinal
    @Value("${application.security.jwt.expiration}")
    protected long VALID_DURATION;

    @NonFinal
    @Value("${application.security.jwt.refresh-expiration}")
    protected long REFRESHABLE_DURATION;

    @NonFinal
    @Value("${app.frontend.url}")
    String frontendUrl;

    // login
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AppException(ErrorCode.PASSWORD_NOT_MATCH);
        }

        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_DISABLED);
        }

        var token = generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    // introspect
    public IntrospectResponse introspect(IntrospectRequest request) throws JOSEException, ParseException {
        var token = request.getToken();
        boolean isValid = true;

        try {
            verifyToken(token, false);
        } catch (AppException e) {
            isValid = false;
        }

        return IntrospectResponse.builder()
                .valid(isValid)
                .build();
    }

    // register
    public String register(UserCreateRequest request) {
        Optional<User> userByUsername = userRepository.findByUsername(request.getUsername());
        if (userByUsername.isPresent()) {
            User user = userByUsername.get();
            String token = user.getVerificationToken();
            if (token != null && !token.isBlank() && user.getEmail().equals(request.getEmail())) {
                throw new AppException(ErrorCode.ACCOUNT_NOT_VERIFIED);
            } else {
                throw new AppException(ErrorCode.USERNAME_EXISTED);
            }
        }
        if (userRepository.existsByEmailAndEnabledTrue(request.getEmail())) {
            throw new AppException(ErrorCode.EMAIL_EXISTED);
        }
        String token = UUID.randomUUID().toString();
        Role role = Role.CUSTOMER;
        if (request.getRole() != null) {
            try {
                role = Role.valueOf(request.getRole().toUpperCase());
                if (role == Role.ADMIN) {
                    role = Role.CUSTOMER; // Force customer if they try to be admin
                }
            } catch (IllegalArgumentException e) {
                role = Role.CUSTOMER;
            }
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .phone(request.getPhone())
                .address(request.getAddress())
                .role(role)
                .enabled(false)
                .verificationToken(token)
                .build();

        userRepository.save(user);
        emailService.sendVerificationEmail(user.getEmail(), token);
        return "Please check your email to verify your account";
    }

    public String verifyEmail(String token) {
        String commonStyle = "<style>" +
                "  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #ebf5fb 0%, #aed6f1 100%); height: 100vh; margin: 0; display: flex; align-items: center; justify-content: center; color: #2c3e50; }" +
                "  .card { background: white; padding: 40px; border-radius: 20px; box-shadow: 0 15px 35px rgba(52, 152, 219, 0.15); text-align: center; max-width: 420px; width: 90%; border: 1px solid #d6eaf8; }" +
                "  h1 { color: #2980b9; margin-bottom: 20px; font-size: 26px; font-weight: 700; }" +
                "  p { color: #5d6d7e; line-height: 1.7; margin-bottom: 30px; font-size: 15px; }" +
                "  .btn { display: inline-block; background: #3498db; color: white; padding: 14px 35px; text-decoration: none; border-radius: 10px; font-weight: bold; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3); }" +
                "  .btn:hover { transform: translateY(-2px); background: #2980b9; box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4); }" +
                "  .icon { font-size: 60px; margin-bottom: 15px; display: block; }" +
                "  .success-icon { color: #27ae60; }" +
                "  .error-icon { color: #e74c3c; }" +
                "  .error-h1 { color: #c0392b; }" +
                "</style>";

        try {
            User user = userRepository.findByVerificationToken(token)
                    .orElseThrow(() -> new AppException(ErrorCode.INVALID_TOKEN));

            user.setEnabled(true);
            user.setVerificationToken(null);
            userRepository.save(user);

            return "<html>" +
                    "<head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>" + commonStyle + "</head>" +
                    "<body>" +
                    "  <div class='card'>" +
                    "    <span class='icon success-icon'>✓</span>" +
                    "    <h1>Xác thực thành công!</h1>" +
                    "    <p>Chúc mừng! Tài khoản của bạn đã được kích hoạt thành công. Bây giờ bạn có thể đăng nhập vào hệ thống.</p>" +
                    "    <a href='" + frontendUrl + "' class='btn'>Đăng nhập ngay</a>" +
                    "  </div>" +
                    "</body>" +
                    "</html>";
        } catch (Exception e) {
            return "<html>" +
                    "<head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>" + commonStyle + "</head>" +
                    "<body>" +
                    "  <div class='card'>" +
                    "    <span class='icon error-icon'>✕</span>" +
                    "    <h1 class='error-h1'>Xác thực thất bại!</h1>" +
                    "    <p>Rất tiếc! Mã xác thực không hợp lệ hoặc đã hết hạn. Vui lòng thử đăng ký lại hoặc liên hệ Hotline: <b>0329223075</b> để được chuyên viên hỗ trợ.</p>" +
                    "    <a href='" + frontendUrl + "/register' class='btn' style='background: #95a5a6;'>Quay lại Đăng ký</a>" +
                    "  </div>" +
                    "</body>" +
                    "</html>";
        }
    }

    public String forgotPassword(com.sa.event_mng.dto.request.ForgotPasswordRequest request) {
        User user = userRepository.findByEmailAndEnabledTrue(request.getEmail())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        String otp = String.format("%06d", new java.util.Random().nextInt(999999));
        user.setVerificationToken(otp); // Reuse verificationToken for OTP
        userRepository.save(user);

        emailService.sendOtpEmail(user.getEmail(), otp);
        return "OTP has been sent to your email";
    }

    public String resetPassword(com.sa.event_mng.dto.request.ResetPasswordRequest request) {
        User user = userRepository.findByEmailAndEnabledTrue(request.getEmail())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (user.getVerificationToken() == null || !user.getVerificationToken().equals(request.getOtp())) {
            throw new AppException(ErrorCode.INVALID_TOKEN);
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setVerificationToken(null);
        userRepository.save(user);

        return "Password has been reset successfully";
    }

    public void logout(LogoutRequest request) throws JOSEException, ParseException {
        try {
            var signedToken = verifyToken(request.getToken(), true);

            String jit = signedToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signedToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken = InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        } catch (AppException e) {
            log.info("Token already expired");
        }
    }

    public AuthenticationResponse refreshToken(RefreshRequest request) throws JOSEException, ParseException {
        var signedJWT = verifyToken(request.getToken(), true);

        var jit = signedJWT.getJWTClaimsSet().getJWTID();
        var expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken = InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

        invalidatedTokenRepository.save(invalidatedToken);

        var username = signedJWT.getJWTClaimsSet().getSubject();

        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.UNAUTHENTICATED));

        var token = generateToken(user);

        return AuthenticationResponse.builder().token(token).build();
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws JOSEException, ParseException {
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());

        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expiryTime = (isRefresh)
                ? new Date(signedJWT.getJWTClaimsSet().getIssueTime().toInstant()
                        .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS).toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);

        if (!(verified && expiryTime.after(new Date())))
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AppException(ErrorCode.UNAUTHENTICATED);

        return signedJWT;
    }

    // gen token
    private String generateToken(User user) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("canhhocit")
                .issueTime(new Date())
                .expirationTime(new Date(
                        Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli()))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", user.getRole().name())
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
