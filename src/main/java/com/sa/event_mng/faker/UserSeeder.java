package com.sa.event_mng.faker;

import com.github.javafaker.Faker;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.Role;
import com.sa.event_mng.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

@Component
public class UserSeeder {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final Faker faker = new Faker(new Locale("vi"));
    private final Random random = new Random();

    public UserSeeder(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void seed() {
        if (userRepository.count() > 1) return;

        List<User> users = new ArrayList<>();

        for (int i = 1; i <= 300; i++) {
            User user = new User();

            user.setUsername("user" + i);
            user.setEmail("user" + i + "@example.com");
            user.setPassword(passwordEncoder.encode("123456"));
            user.setFullName(faker.name().fullName());
            user.setPhone("09" + String.format("%08d", random.nextInt(100000000)));
            user.setAddress(faker.address().fullAddress());
            user.setRole(randomRole());
            user.setEnabled(true);
            user.setVerificationToken(null);

            users.add(user);
        }

        userRepository.saveAll(users);
        System.out.println("Seeded " + users.size() + " users");
    }

    private Role randomRole() {
        Role[] roles = Role.values();
        return roles[random.nextInt(roles.length)];
    }
}
