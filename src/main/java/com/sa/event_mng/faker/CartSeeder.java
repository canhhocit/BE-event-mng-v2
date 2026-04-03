package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Cart;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.CartStatus;
import com.sa.event_mng.model.enums.Role;
import com.sa.event_mng.repository.CartRepository;
import com.sa.event_mng.repository.UserRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class CartSeeder {

    private final CartRepository cartRepository;
    private final UserRepository userRepository;
    private final Random random = new Random();

    public CartSeeder(CartRepository cartRepository, UserRepository userRepository) {
        this.cartRepository = cartRepository;
        this.userRepository = userRepository;
    }

    public void seed() {
        if (cartRepository.count() > 0) return;

        List<User> users = userRepository.findByRole(Role.CUSTOMER);
        if (users.isEmpty()) {
            System.out.println("No users found. Seed users first.");
            return;
        }

        List<Cart> carts = new ArrayList<>();

        for (User user : users) {
            Cart cart = new Cart();
            cart.setCustomer(user);
            cart.setStatus(randomCartStatus());
            cart.setItems(new ArrayList<>());
            carts.add(cart);
        }

        cartRepository.saveAll(carts);
        System.out.println("Seeded " + carts.size() + " carts");
    }

    private CartStatus randomCartStatus() {
        CartStatus[] statuses = CartStatus.values();
        return statuses[random.nextInt(statuses.length)];
    }
}
