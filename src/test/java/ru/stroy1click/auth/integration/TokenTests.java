package ru.stroy1click.auth.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.dto.Role;

import static org.mockito.Mockito.when;

@Import({TestcontainersConfiguration.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenTests {

    @Autowired
    private TestRestTemplate testRestTemplate;

    @MockitoBean
    private UserClient userClient;

    @Test
    public void refreshAccessToken_ShouldReturnNewTokens_WhenValidRefreshToken() {
        String refreshToken = "ba9a4691-ff6d-45eb-857f-1e39079ebd60";
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(refreshToken));

        when(this.userClient.getByEmail("mike_thompson@gmail.com")).thenReturn(new UserDto(1L,"Mike", "Thompson", "mike_thompson@gmail.com", "{noop}password123", true, Role.ROLE_USER));

        ResponseEntity<JwtResponse> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/access",
                HttpMethod.POST,
                httpEntity,
                JwtResponse.class
        );

        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertNotNull(responseEntity.getBody().getAccessToken());
        Assertions.assertNotNull(responseEntity.getBody().getRefreshToken());
    }

    @Test
    public void refreshToken_ShouldExtendTokenExpiration_WhenValidRefreshToken(){
        String refreshToken = "40f2a44f-31ed-4593-97fe-ab775e309988";
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(refreshToken));

        ResponseEntity<String> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/refresh-token",
                HttpMethod.PATCH,
                httpEntity,
                String.class
        );

        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertEquals("Refresh Token продлён", responseEntity.getBody());
    }

    @Test
    public void refreshAccessToken_ShouldReturnValidationError_WhenTokenIsBlank() {
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(""));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/access",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Refresh token не может быть пустым"));
    }

    @Test
    public void refreshToken_ShouldReturnValidationError_WhenTokenIsBlank() {
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest(""));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/refresh-token",
                HttpMethod.PATCH,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Refresh token не может быть пустым"));
    }

    @Test
    public void refreshAccessToken_ShouldReturnValidationError_WhenTokenLengthIsInvalid() {
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest("invalid-token"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/access",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Длина токена должна составлять 36 символов"));
    }

    @Test
    public void refreshToken_ShouldReturnValidationError_WhenTokenLengthIsInvalid() {
        HttpEntity<RefreshTokenRequest> httpEntity = new HttpEntity<>(new RefreshTokenRequest("invalid-token"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/tokens/refresh-token",
                HttpMethod.PATCH,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Длина токена должна составлять 36 символов"));
    }
}
