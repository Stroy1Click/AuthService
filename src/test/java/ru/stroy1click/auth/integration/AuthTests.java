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
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.Role;

import static org.mockito.Mockito.when;

@Import({TestcontainersConfiguration.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthTests {

    @Autowired
    private TestRestTemplate testRestTemplate;

    @MockitoBean
    private UserClient userClient;

    @Test
    public void registration_ShouldRegisterUser_WhenValidData(){
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("kate_thompson@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        when(this.userClient.create(httpEntity.getBody())).thenReturn(new UserDto());

        ResponseEntity<String> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                String.class
        );

        System.out.println(responseEntity);

        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertEquals("Пользователь зарегистрирован", responseEntity.getBody());
    }

    @Test
    public void login_ShouldReturnTokens_WhenValidCredentials(){
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("mike_thompson@gmail.com", "password123"));

        when(this.userClient.getByEmail("mike_thompson@gmail.com")).thenReturn(new UserDto(1L,"Mike", "Thompson", "mike_thompson@gmail.com", "{noop}password123", true,Role.ROLE_USER));

        ResponseEntity<JwtResponse> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                JwtResponse.class
        );

        System.out.println(responseEntity);

        Assertions.assertTrue(responseEntity.getStatusCode().is2xxSuccessful());
        Assertions.assertNotNull(responseEntity.getBody().getAccessToken());
        Assertions.assertNotNull(responseEntity.getBody().getRefreshToken());
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenFirstNameIsBlank() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Имя не может быть пустым"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenFirstNameIsTooShort() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("K")
                .lastName("Thompson")
                .email("kate_thompson@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина имени составляет 2 символа, максимальная - 30 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenFirstNameIsTooLong() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("K".repeat(31))
                .lastName("Thompson")
                .email("kate_thompson11@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина имени составляет 2 символа, максимальная - 30 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenLastNameIsBlank() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("")
                .email("kate_thompson7@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Фамилия не может быть пустой"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenLastNameIsTooShort() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("T")
                .email("kate_thompson6@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина фамилии составляет 2 символа, максимальная - 30 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenLastNameIsTooLong() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("T".repeat(31))
                .email("kate_thompson9@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина фамилии составляет 2 символа, максимальная - 30 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenEmailIsBlank() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Электронная почта не может быть пустой"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenEmailIsInvalid() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("invalid-email")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Электронная почта должна быть валидной"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenEmailIsTooShort() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("a@b.co")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenEmailIsTooLong() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("a".repeat(45) + "@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenPasswordIsBlank() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("kate_thompson4@gmail.com")
                .password("")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Пароль не может быть пустым"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenPasswordIsTooShort() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate2")
                .lastName("Thompson2")
                .email("kate_thompson2@gmail.com")
                .password("pass123")
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenPasswordIsTooLong() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("kate_thompson5@gmail.com")
                .password("p".repeat(61))
                .emailConfirmed(false)
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenEmailConfirmedIsNull() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate")
                .lastName("Thompson")
                .email("kate_thompson8@gmail.com")
                .password("password123")
                .role(Role.ROLE_USER)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Статус подтверждения не может быть пустым"));
    }

    @Test
    public void registration_ShouldReturnValidationError_WhenRoleIsNull() {
        HttpEntity<UserDto> httpEntity = new HttpEntity<>(UserDto.builder()
                .firstName("Kate1")
                .lastName("Thompson1")
                .email("kate_thompson1@gmail.com")
                .password("password123")
                .emailConfirmed(false)
                .build());

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/registration",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Роль не может быть пустой"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenEmailIsBlank() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("", "password123"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Электронная почта не может быть пустой"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenEmailIsInvalid() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("invalid-email", "password123"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Электронная почта должна быть валидной"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenEmailIsTooShort() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("a@b.co", "password123"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenEmailIsTooLong() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("a".repeat(45) + "@gmail.com", "password123"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenPasswordIsBlank() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("mike_thompson@gmail.com", ""));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Пароль не может быть пустым"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenPasswordIsTooShort() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("mike_thompson@gmail.com", "pass123"));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов"));
    }

    @Test
    public void login_ShouldReturnValidationError_WhenPasswordIsTooLong() {
        HttpEntity<AuthRequest> httpEntity = new HttpEntity<>(new AuthRequest("mike_thompson@gmail.com", "p".repeat(61)));

        ResponseEntity<ProblemDetail> responseEntity = this.testRestTemplate.exchange(
                "/api/v1/auth/login",
                HttpMethod.POST,
                httpEntity,
                ProblemDetail.class
        );

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        Assertions.assertNotNull(responseEntity.getBody());
        Assertions.assertEquals("Ошибка валидации", responseEntity.getBody().getTitle());
        Assertions.assertTrue(responseEntity.getBody().getDetail().contains("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов"));
    }

}