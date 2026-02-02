package ru.stroy1click.auth.unit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.exception.NotFoundException;
import ru.stroy1click.auth.exception.ValidationException;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.service.JwtService;
import ru.stroy1click.auth.service.RefreshTokenService;
import ru.stroy1click.auth.service.impl.AuthServiceImpl;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthTest {

    @Mock
    private UserClient userClient;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private MessageSource messageSource;

    @InjectMocks
    private AuthServiceImpl authService;

    private UserDto userDto;
    private AuthRequest authRequest;
    private RefreshTokenRequest refreshTokenRequest;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "password";
    private static final String ENCODED_PASSWORD = "encodedPassword";
    private static final String GENERATED_TOKEN = "generatedToken";
    private static final String REFRESH_TOKEN = "refreshToken";

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        this.userDto = new UserDto();
        this.userDto.setPassword(ENCODED_PASSWORD);

        this.authRequest = new AuthRequest();
        this.authRequest.setEmail(TEST_EMAIL);
        this.authRequest.setPassword(TEST_PASSWORD);

        this.refreshTokenRequest = new RefreshTokenRequest();
        this.refreshTokenRequest.setRefreshToken(REFRESH_TOKEN);
    }

    @Test
    public void generateToken_ShouldGenerateToken_WhenUserExists() {
        // Given
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.jwtService.generate(userDto)).thenReturn(GENERATED_TOKEN);

        // When
        String token = this.authService.generateToken(TEST_EMAIL);

        // Then
        assertEquals(GENERATED_TOKEN, token);
        verify(this.userClient).getByEmail(TEST_EMAIL);
        verify(this.jwtService).generate(userDto);
    }

    @Test
    public void generateToken_ShouldThrowNotFoundException_WhenUserNotExists() {
        // Given
        String email = "nonexistent@example.com";
        when(this.userClient.getByEmail(email)).thenThrow(new NotFoundException("User not found"));

        // When & Then
        assertThrows(NotFoundException.class, () -> this.authService.generateToken(email));
    }

    @Test
    public void logout_ShouldDeleteRefreshToken_WhenCalled() {
        // When
        this.authService.logout(refreshTokenRequest);

        // Then
        verify(this.refreshTokenService).delete(REFRESH_TOKEN);
    }

    @Test
    public void login_ShouldReturnUser_WhenUserExistsAndPasswordMatches() {
        // Given
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

        // When
        UserDto result = this.authService.login(authRequest);

        // Then
        assertEquals(userDto, result);
    }

    @Test
    public void login_ShouldThrowNotFoundException_WhenUserNotExists() {
        // Given
        String nonExistentEmail = "nonexistent@example.com";
        authRequest.setEmail(nonExistentEmail);
        when(this.userClient.getByEmail(nonExistentEmail)).thenThrow(new NotFoundException("User not found"));

        // When & Then
        assertThrows(NotFoundException.class, () -> this.authService.login(authRequest));
    }

    @Test
    public void login_ShouldThrowValidationException_WhenPasswordDoesNotMatch() {
        // Given
        String wrongPassword = "wrongPassword";
        authRequest.setPassword(wrongPassword);
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.passwordEncoder.matches(wrongPassword, ENCODED_PASSWORD)).thenReturn(false);
        when(this.messageSource.getMessage("error.password.incorrect", null, Locale.getDefault()))
                .thenReturn("Password is incorrect");

        // When & Then
        assertThrows(ValidationException.class, () -> this.authService.login(authRequest));
    }
}
