package ru.stroy1click.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class Stroy1ClickAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(Stroy1ClickAuthServiceApplication.class, args);
    }
}
