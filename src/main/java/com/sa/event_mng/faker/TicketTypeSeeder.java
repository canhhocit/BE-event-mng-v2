package com.sa.event_mng.faker;

import com.github.javafaker.Faker;
import com.sa.event_mng.model.entity.Event;
import com.sa.event_mng.model.entity.TicketType;
import com.sa.event_mng.repository.EventRepository;
import com.sa.event_mng.repository.TicketTypeRepository;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

@Component
public class TicketTypeSeeder {

    private final TicketTypeRepository ticketTypeRepository;
    private final EventRepository eventRepository;

    private final Faker faker = new Faker(new Locale("vi"));
    private final Random random = new Random();

    public TicketTypeSeeder(TicketTypeRepository ticketTypeRepository, EventRepository eventRepository) {
        this.ticketTypeRepository = ticketTypeRepository;
        this.eventRepository = eventRepository;
    }

    public void seed() {
        if (ticketTypeRepository.count() > 0) return;

        List<Event> events = eventRepository.findAll();
        if (events.isEmpty()) {
            System.out.println("No events found. Seed events first.");
            return;
        }

        List<TicketType> ticketTypes = new ArrayList<>();

        for (Event event : events) {
            int numberOfTypes = random.nextInt(3) + 1;

            for (int i = 0; i < numberOfTypes; i++) {
                int totalQuantity = random.nextInt(451) + 50;
                int sold = random.nextInt(totalQuantity + 1);
                int remainingQuantity = totalQuantity - sold;

                TicketType ticketType = new TicketType();
                ticketType.setEvent(event);
                ticketType.setName(generateTicketTypeName(i));
                ticketType.setPrice(randomPrice(i));
                ticketType.setTotalQuantity(totalQuantity);
                ticketType.setRemainingQuantity(remainingQuantity);
                ticketType.setDescription(faker.lorem().sentence(12));

                ticketTypes.add(ticketType);
            }
        }

        ticketTypeRepository.saveAll(ticketTypes);
        System.out.println("Seeded " + ticketTypes.size() + " ticket types");
    }

    private String generateTicketTypeName(int index) {
        String[] names = {"Vé Thường", "Vé VIP", "Vé Premium", "Vé Early Bird", "Vé Student"};
        if (index < names.length) {
            return names[index];
        }
        return names[random.nextInt(names.length)];
    }

    private BigDecimal randomPrice(int index) {
        long[] basePrices = {99000, 199000, 399000, 149000, 79000};
        long base = index < basePrices.length
                ? basePrices[index]
                : basePrices[random.nextInt(basePrices.length)];

        long extra = random.nextInt(200) * 1000L;
        return BigDecimal.valueOf(base + extra);
    }
}
