package ru.stroy1click.auth.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.config.TestcontainersConfiguration;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.Role;

import static org.mockito.Mockito.when;

@Import({TestcontainersConfiguration.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerIT {

    @Autowired
    private TestRestTemplate testRestTemplate;

    @MockitoBean
    private UserClient userClient;

    @Test
    public void registration_WhenValidDataProvided_ShouldRegisterUser(){
        //Arrange
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("kate_thompson@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());
        when(this.userClient.create(httpEntity.getBody())).thenReturn(new UserDto());

        //Act
        ResponseEntity<String> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                String.class
        );

        //Assert
        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertEquals("Пользователь зарегистрирован", responseEntity.getBody());
    }

    @Test
    public void login_WhenValidCredentialsProvided_ShouldReturnTokens(){
        //Arrange
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("mike_thompson@gmail.com", "password123"));
        when(this.userClient.getByEmail("mike_thompson@gmail.com")).thenReturn(new UserDto(1L,"Mike", "Thompson", "mike_thompson@gmail.com", "{noop}password123", true,Role.ROLE_USER));

        //Act
        ResponseEntity<JwtResponse> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                JwtResponse.class
        );

        //Assert
        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertNotNull(responseEntity.getBody().getAccessToken());
        Assertions.assertNotNull(responseEntity.getBody().getRefreshToken());
    }
}