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
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.dto.Role;

import static org.mockito.Mockito.when;

@Import({TestcontainersConfiguration.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenControllerIT {

    @Autowired
    private TestRestTemplate testRestTemplate;

    @MockitoBean
    private UserClient userClient;

    @Test
    public void refreshAccessToken_WhenValidDataProvidedAndRefreshTokenExists_ShouldReturnNewTokens() {
        //Arrange
        String refreshToken = "ba9a4691-ff6d-45eb-857f-1e39079ebd60";
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(refreshToken));

        when(this.userClient.getByEmail("mike_thompson@gmail.com")).thenReturn(new UserDto(1L,"Mike", "Thompson", "mike_thompson@gmail.com", "{noop}password123", true, Role.ROLE_USER));

        //Act
        ResponseEntity<JwtResponse> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/access",
                HttpMethod.POST,
                httpEntity,
                JwtResponse.class
        );

        //Assert
        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertNotNull(responseEntity.getBody().getAccessToken());
        Assertions.assertNotNull(responseEntity.getBody().getRefreshToken());
    }

    @Test
    public void refreshToken_WhenValidDataProvidedAndRefreshTokenExists_ShouldExtendTokenExpiration(){
        //Arrange
        String refreshToken = "40f2a44f-31ed-4593-97fe-ab775e309988";
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(refreshToken));

        //Act
        ResponseEntity<String> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/refresh-token",
                HttpMethod.PATCH,
                httpEntity,
                String.class
        );

        //Assert
        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertEquals("Refresh Token продлён", responseEntity.getBody());
    }
}
