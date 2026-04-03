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
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new AppException(ErrorCode.INVALID_TOKEN));

        user.setEnabled(true);
        user.setVerificationToken(null);
        userRepository.save(user);

        return "Email đã được xác thực thành công. Vui lòng quay lại ứng dụng để đăng nhập: http://localhost:5173";
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
