package com.sa.event_mng;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class EventMngApplication {

	public static void main(String[] args) {
		SpringApplication.run(EventMngApplication.class, args);
	}

}
