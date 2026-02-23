package ru.stroy1click.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.stroy1click.common.service.JwtService;
import ru.stroy1click.common.service.impl.JwtServiceImpl;

@Configuration
public class JwtConfig {

    @Value(value = "${jwt.secret}")
    public String SECRET;

    @Bean
    public JwtService jwtService(){
        return new JwtServiceImpl(SECRET);
    }
}
