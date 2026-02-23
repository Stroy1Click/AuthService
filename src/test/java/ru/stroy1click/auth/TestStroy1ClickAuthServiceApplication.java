package ru.stroy1click.auth;

import org.springframework.boot.SpringApplication;
import ru.stroy1click.auth.config.TestcontainersConfiguration;

public class TestStroy1ClickAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.from(Stroy1ClickAuthServiceApplication::main)
                .with(TestcontainersConfiguration.class)
                .run(args);
    }
}
