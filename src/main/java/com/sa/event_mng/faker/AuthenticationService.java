// package com.sa.event_mng.faker;

// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Service;

// import com.sa.event_mng.repository.InvalidatedTokenRepository;
// import com.sa.event_mng.repository.UserRepository;
// import com.sa.event_mng.service.EmailService;

// import lombok.extern.slf4j.Slf4j;

// @Service
// @Slf4j
// public class AuthenticationService {

//     private final UserRepository userRepository;
//     private final PasswordEncoder passwordEncoder;
//     private final EmailService emailService;
//     private final InvalidatedTokenRepository invalidatedTokenRepository;

//     public AuthenticationService(UserRepository userRepository,
//                                  PasswordEncoder passwordEncoder,
//                                  EmailService emailService,
//                                  InvalidatedTokenRepository invalidatedTokenRepository) {
//         this.userRepository = userRepository;
//         this.passwordEncoder = passwordEncoder;
//         this.emailService = emailService;
//         this.invalidatedTokenRepository = invalidatedTokenRepository;
//     }
// }
