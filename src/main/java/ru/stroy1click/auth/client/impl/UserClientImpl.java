package ru.stroy1click.auth.client.impl;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.common.util.ValidationErrorUtils;
import ru.stroy1click.common.exception.ServiceUnavailableException;

@Slf4j
@Component
@CircuitBreaker(name = "userClient")
public class UserClientImpl implements UserClient {

    private final RestClient restClient;

    public UserClientImpl(@Value("${url.user}") String url){
        this.restClient = RestClient.builder()
                .baseUrl(url)
                .build();
    }

    @Override
    public UserDto getByEmail(String email) {
        log.info("getByEmail {}", email);
        try {
            return this.restClient.get()
                    .uri("?email={email}", email)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError,(request, response) -> {
                        ValidationErrorUtils.validateStatus(response);
                    })
                    .body(UserDto.class);
        } catch (ResourceAccessException e){
            log.error("getByEmail error", e);
            throw new ServiceUnavailableException();
        }
    }

    @Override
    public UserDto create(UserDto userDto) {
        log.info("create {}", userDto);
        try {
            return this.restClient.post()
                    .body(userDto)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (request, response) -> {
                        ValidationErrorUtils.validateStatus(response);
                    })
                    .body(UserDto.class);
        } catch (ResourceAccessException e){
            log.error("create error", e);
            throw new ServiceUnavailableException();
        }
    }
}
