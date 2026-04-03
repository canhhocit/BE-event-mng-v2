package com.sa.event_mng.faker;

import com.sa.event_mng.model.entity.Cart;
import com.sa.event_mng.model.entity.CartItem;
import com.sa.event_mng.model.entity.TicketType;
import com.sa.event_mng.repository.CartRepository;
import com.sa.event_mng.repository.TicketTypeRepository;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class CartItemSeeder {

    private final CartRepository cartRepository;
    private final TicketTypeRepository ticketTypeRepository;
    private final Random random = new Random();

    public CartItemSeeder(CartRepository cartRepository, TicketTypeRepository ticketTypeRepository) {
        this.cartRepository = cartRepository;
        this.ticketTypeRepository = ticketTypeRepository;
    }

    public void seed() {
        List<Cart> carts = cartRepository.findAll();
        List<TicketType> ticketTypes = ticketTypeRepository.findAll();

        if (carts.isEmpty()) {
            System.out.println("No carts found. Seed carts first.");
            return;
        }

        if (ticketTypes.isEmpty()) {
            System.out.println("No ticket types found. Seed ticket types first.");
            return;
        }

        int createdCount = 0;

        for (Cart cart : carts) {
            if (cart.getItems() != null && !cart.getItems().isEmpty()) {
                continue;
            }

            int itemCount = random.nextInt(3) + 1;
            List<CartItem> items = new ArrayList<>();

            for (int i = 0; i < itemCount; i++) {
                TicketType ticketType = ticketTypes.get(random.nextInt(ticketTypes.size()));
                int quantity = Math.max(1, random.nextInt(4));

                if (ticketType.getRemainingQuantity() == null || ticketType.getRemainingQuantity() <= 0) {
                    continue;
                }

                quantity = Math.min(quantity, ticketType.getRemainingQuantity());

                BigDecimal unitPrice = ticketType.getPrice();
                BigDecimal subtotal = unitPrice.multiply(BigDecimal.valueOf(quantity));

                CartItem item = new CartItem();
                item.setCart(cart);
                item.setTicketType(ticketType);
                item.setQuantity(quantity);
                item.setUnitPrice(unitPrice);
                item.setSubtotal(subtotal);

                items.add(item);
                createdCount++;
            }

            cart.setItems(items);
        }

        cartRepository.saveAll(carts);
        System.out.println("Seeded " + createdCount + " cart items");
    }
}
