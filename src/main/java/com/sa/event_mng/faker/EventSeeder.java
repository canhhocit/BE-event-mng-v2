package com.sa.event_mng.faker;

import com.github.javafaker.Faker;
import com.sa.event_mng.model.entity.Category;
import com.sa.event_mng.model.entity.Event;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.EventStatus;
import com.sa.event_mng.model.enums.Role;
import com.sa.event_mng.repository.CategoryRepository;
import com.sa.event_mng.repository.EventRepository;
import com.sa.event_mng.repository.UserRepository;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
public class EventSeeder {
    private final EventRepository eventRepository;
    private final CategoryRepository categoryRepository;
    private final UserRepository userRepository;

    private final Faker faker = new Faker();
    private final Random random = new Random();

    public EventSeeder(
            EventRepository eventRepository,
            CategoryRepository categoryRepository,
            UserRepository userRepository
    ) {
        this.eventRepository = eventRepository;
        this.categoryRepository = categoryRepository;
        this.userRepository = userRepository;
    }

    public void seed() {
        if (eventRepository.count() > 0) return;

        List<Category> categories = categoryRepository.findAll();
        List<User> users = userRepository.findByRole(Role.ORGANIZER);

        if (categories.isEmpty()) {
            System.out.println("No categories found. Seed categories first.");
            return;
        }

        if (users.isEmpty()) {
            System.out.println("No users found. Seed users first.");
            return;
        }

        List<Event> events = new ArrayList<>();

        for (int i = 0; i < 300; i++) {
            Category category = categories.get(random.nextInt(categories.size()));
            User organizer = users.get(random.nextInt(users.size()));

            LocalDateTime startTime = LocalDateTime.now()
                    .plusDays(random.nextInt(60) - 20)
                    .plusHours(random.nextInt(24));

            LocalDateTime endTime = startTime.plusHours(random.nextInt(6) + 1);

            Event event = new Event();
            event.setName(generateEventName());
            event.setCategory(category);
            event.setOrganizer(organizer);
            event.setLocation(faker.address().cityName());
            event.setStartTime(startTime);
            event.setEndTime(endTime);
            event.setDescription(faker.lorem().paragraph(3));
            event.setStatus(randomEventStatus(startTime, endTime));

            events.add(event);
        }

        eventRepository.saveAll(events);
        System.out.println("Seeded " + events.size() + " events");
    }

    private String generateEventName() {
        String[] prefixes = {
                "Lễ hội", "Workshop", "Hội thảo", "Triển lãm", "Sự kiện",
                "Concert", "Giải đấu", "Ngày hội", "Chương trình", "Talkshow"
        };

        String[] topics = {
                "Âm nhạc", "Công nghệ", "Khởi nghiệp", "Ẩm thực", "Thời trang",
                "Game", "Giáo dục", "Du lịch", "Nhiếp ảnh", "Sáng tạo"
        };

        return prefixes[random.nextInt(prefixes.length)] + " " +
                topics[random.nextInt(topics.length)] + " " +
                (2025 + random.nextInt(3));
    }

    private EventStatus randomEventStatus(LocalDateTime startTime, LocalDateTime endTime) {
        LocalDateTime now = LocalDateTime.now();
        
        if (endTime.isBefore(now)) return EventStatus.COMPLETED;
        if (startTime.isBefore(now)) return EventStatus.OPENING;
        
        EventStatus[] futureStatuses = {EventStatus.PENDING, EventStatus.UPCOMING, EventStatus.CANCELLED};
        return futureStatuses[random.nextInt(futureStatuses.length)];
    }
}
