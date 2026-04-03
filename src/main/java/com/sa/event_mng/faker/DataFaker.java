//package com.sa.event_mng.faker;
//
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class DataFaker {
//
//    @Bean
//    CommandLineRunner seedDatabase(
//            CategorySeeder categorySeeder,
//            UserSeeder userSeeder,
//            EventSeeder eventSeeder,
//            TicketTypeSeeder ticketTypeSeeder,
//            CartSeeder cartSeeder,
//            CartItemSeeder cartItemSeeder,
//            OrderSeeder orderSeeder,
//            OrderItemSeeder orderItemSeeder,
//            TicketSeeder ticketSeeder
//    ) {
//        return args -> {
//            System.out.println("=== START SEED DATABASE ===");
//
//            categorySeeder.seed();
//            userSeeder.seed();
//            eventSeeder.seed();
//            ticketTypeSeeder.seed();
//            cartSeeder.seed();
//            cartItemSeeder.seed();
//            orderSeeder.seed();
//            orderItemSeeder.seed();
//            ticketSeeder.seed();
//
//            System.out.println("=== END SEED DATABASE ===");
//        };
//    }
//}