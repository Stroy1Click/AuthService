package ru.stroy1click.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.Role;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.service.impl.AuthServiceImpl;
import ru.stroy1click.common.exception.NotFoundException;
import ru.stroy1click.common.exception.ValidationException;
import ru.stroy1click.common.service.JwtService;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

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
        userDto = new UserDto();
        userDto.setPassword(ENCODED_PASSWORD);
        userDto.setRole(Role.ROLE_USER);

        authRequest = new AuthRequest();
        authRequest.setEmail(TEST_EMAIL);
        authRequest.setPassword(TEST_PASSWORD);

        refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken(REFRESH_TOKEN);
    }

    @Test
    public void generateToken_WhenUserExists_ShouldGenerateToken() {
        //Arrange
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.jwtService.generate(userDto.getEmail(), userDto.getRole().toString(), userDto.getEmailConfirmed()))
                .thenReturn(GENERATED_TOKEN);

        //Act
        String token = this.authService.generateToken(TEST_EMAIL);

        //Assert
        assertEquals(GENERATED_TOKEN, token);
        verify(this.userClient).getByEmail(TEST_EMAIL);
        verify(this.jwtService).generate(userDto.getEmail(), userDto.getRole().toString(), userDto.getEmailConfirmed());
    }

    @Test
    public void generateToken_WhenUserNotExists_ShouldThrowNotFoundException() {
        //Arrange
        String email = "nonexistent@example.com";
        when(this.userClient.getByEmail(email)).thenThrow(new NotFoundException("User not found"));

        //Act & Assert
        assertThrows(NotFoundException.class, () -> this.authService.generateToken(email));
    }

    @Test
    public void logout_WhenCalled_ShouldDeleteRefreshToken() {
        //Act
        this.authService.logout(refreshTokenRequest);

        //Assert
        verify(this.refreshTokenService).delete(REFRESH_TOKEN);
    }

    @Test
    public void login_WhenUserExistsAndPasswordMatches_ShouldReturnUse() {
        //Arrange
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.passwordEncoder.matches(TEST_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

        //Act
        UserDto result = this.authService.login(authRequest);

        //Assert
        assertEquals(userDto, result);
    }

    @Test
    public void login_WhenUserDoesNotExist_ShouldThrowNotFoundException() {
        //Arrange
        String nonExistentEmail = "nonexistent@example.com";
        authRequest.setEmail(nonExistentEmail);
        when(this.userClient.getByEmail(nonExistentEmail)).thenThrow(new NotFoundException("User not found"));

        //Act & Assert
        assertThrows(NotFoundException.class, () -> this.authService.login(authRequest));
    }

    @Test
    public void login_WhenPasswordDoesNotMatch_ShouldThrowValidationException() {
        //Arrange
        String wrongPassword = "wrongPassword";
        authRequest.setPassword(wrongPassword);
        when(this.userClient.getByEmail(TEST_EMAIL)).thenReturn(userDto);
        when(this.passwordEncoder.matches(wrongPassword, ENCODED_PASSWORD)).thenReturn(false);
        when(this.messageSource.getMessage("error.password.incorrect", null, Locale.getDefault()))
                .thenReturn("Password is incorrect");

        //Act & Assert
        assertThrows(ValidationException.class, () -> this.authService.login(authRequest));
    }
}
