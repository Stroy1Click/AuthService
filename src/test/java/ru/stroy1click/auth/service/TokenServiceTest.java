package ru.stroy1click.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.dto.Role;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.entity.RefreshToken;
import ru.stroy1click.auth.repository.RefreshTokenRepository;
import ru.stroy1click.auth.service.impl.RefreshTokenServiceImpl;
import ru.stroy1click.common.exception.NotFoundException;
import ru.stroy1click.common.exception.ValidationException;
import ru.stroy1click.common.service.JwtService;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserClient userClient;

    @Mock
    private MessageSource messageSource;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private UserDto userDto;

    private RefreshToken refreshToken;

    private RefreshTokenRequest refreshTokenRequest;

    @BeforeEach
    public void setUp() {
        userDto = new UserDto();
        userDto.setId(1L);
        userDto.setEmail("test@example.com");
        userDto.setRole(Role.ROLE_USER);

        refreshToken = new RefreshToken();
        refreshToken.setUserEmail("test@example.com");
        refreshToken.setToken("test-token");
        refreshToken.setExpiryDate(Instant.now().plusSeconds(600000));

        refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken("test-token");
    }

    @Test
    public void createRefreshToken_WhenUserExistsAndSessionsLessThanSix_ShouldCreateToken() {
        //Arrange
        when(this.refreshTokenRepository.countByUserEmail("test@example.com")).thenReturn(5);
        
        RefreshToken savedToken = RefreshToken.builder()
                .userEmail("test@example.com")
                .token("test-token")
                .expiryDate(Instant.now().plusSeconds(600000))
                .build();
        
        when(this.refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(savedToken);

        //Act
        RefreshToken result = this.refreshTokenService.createRefreshToken("test@example.com");

        //Assert
        assertNotNull(result);
        assertEquals(userDto.getEmail(), result.getUserEmail());
        verify(this.refreshTokenRepository).countByUserEmail("test@example.com");
        verify(this.refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    public void createRefreshToken_WhenUserHasMoreThanSixSessions_ShouldThrowValidationException() {
        //Arrange
        when(this.refreshTokenRepository.countByUserEmail("test@example.com")).thenReturn(7);

        //Act & Assert
        assertThrows(ValidationException.class, () -> this.refreshTokenService.createRefreshToken("test@example.com"));
        verify(this.refreshTokenRepository).countByUserEmail("test@example.com");
    }

    @Test
    public void delete_WhenTokenExists_ShouldDeleteTokenByTokenString() {
        when(this.refreshTokenRepository.findFirstByToken("test-token"))
                .thenReturn(Optional.of(refreshToken));

        //Act
        this.refreshTokenService.delete("test-token");

        //Assert
        verify(this.refreshTokenRepository).delete(refreshToken);
    }

    @Test
    public void delete_WhenTokenDoesNotExist_ShouldThrowNotFoundException() {
        //Arrange
        when(this.refreshTokenRepository.findFirstByToken("not-exist-token"))
                .thenReturn(Optional.empty());

        //Act
        assertThrows(NotFoundException.class,
                () -> this.refreshTokenService.delete("not-exist-token"));
    }

    @Test
    public void deleteAll_WhenCalled_ShouldDeleteAllTokensForUser() {
        doNothing().when(this.refreshTokenRepository).deleteAllByUserEmail("test@example.com");

        //Act
        this.refreshTokenService.deleteAll("test@example.com");

        //Assert
        verify(this.refreshTokenRepository).deleteAllByUserEmail("test@example.com");
    }

    @Test
    public void extendTheExpirationDate_WhenTokenExists_ShouldExtendExpiration() {
        //Arrange
        Instant oldExpiryDate = Instant.now();
        refreshToken.setExpiryDate(oldExpiryDate);
        when(this.refreshTokenRepository.findFirstByToken("test-token")).thenReturn(Optional.of(refreshToken));

        //Act
        this.refreshTokenService.extendTheExpirationDate(refreshTokenRequest);

        //Assert
        verify(this.refreshTokenRepository).findFirstByToken("test-token");
        assertTrue(refreshToken.getExpiryDate().isAfter(oldExpiryDate));
    }

    @Test
    public void extendTheExpirationDate_WhenTokenDoesNotExist_ShouldThrowNotFoundException() {
        //Arrange
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("nonexistent-token");
        when(this.refreshTokenRepository.findFirstByToken("nonexistent-token")).thenReturn(Optional.empty());
        when(this.messageSource.getMessage(eq("error.refresh_token.not_found"), any(), any()))
                .thenReturn("Refresh token not found");

        //Act & Assert
        assertThrows(NotFoundException.class, () -> this.refreshTokenService.extendTheExpirationDate(request));
        verify(this.refreshTokenRepository).findFirstByToken("nonexistent-token");
    }

    @Test
    public void refreshAccessToken_WhenTokenExistsAndNotExpired_ShouldReturnJwtResponse() {
        //Arrange
        when(this.refreshTokenRepository.findFirstByToken("test-token")).thenReturn(Optional.of(refreshToken));
        when(this.jwtService.generate(userDto.getEmail(), userDto.getRole().toString(), userDto.getEmailConfirmed())).thenReturn("new access token");
        when(this.userClient.getByEmail(refreshToken.getUserEmail())).thenReturn(this.userDto);

        //Act
        JwtResponse result = this.refreshTokenService.refreshAccessToken(this.refreshTokenRequest);

        //Assert
        assertNotNull(result);
        assertEquals("new access token", result.getAccessToken());
        assertEquals("test-token", result.getRefreshToken());
        verify(this.refreshTokenRepository).findFirstByToken("test-token");
        verify(this.jwtService).generate(userDto.getEmail(), userDto.getRole().toString(), userDto.getEmailConfirmed());
    }

    @Test
    public void refreshAccessToken_WhenTokenDoesNotExist_ShouldThrowNotFoundException() {
        //Arrange
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("nonexistent-token");
        when(this.refreshTokenRepository.findFirstByToken("nonexistent-token")).thenReturn(Optional.empty());
        when(this.messageSource.getMessage(eq("error.refresh_token.not_found"), any(), any()))
                .thenReturn("Refresh token not found");

        //Act & Assert
        assertThrows(NotFoundException.class, () -> this.refreshTokenService.refreshAccessToken(request));
        verify(this.refreshTokenRepository).findFirstByToken("nonexistent-token");
    }

    @Test
    public void refreshAccessToken_WhenTokenExpired_ShouldThrowValidationException() {
        //Arrange
        String expiredToken = "expired-token";
        RefreshToken expiredRefreshToken = new RefreshToken();
        expiredRefreshToken.setUserEmail("test@example.com");
        expiredRefreshToken.setToken(expiredToken);
        expiredRefreshToken.setExpiryDate(Instant.now().minusSeconds(600000)); // Expired

        RefreshTokenRequest expiredRequest = new RefreshTokenRequest();
        expiredRequest.setRefreshToken(expiredToken);

        when(this.refreshTokenRepository.findFirstByToken(expiredToken)).thenReturn(Optional.of(expiredRefreshToken));
        when(this.messageSource.getMessage(eq("error.refresh_token.expired"), any(), any()))
                .thenReturn("Refresh token expired");

        //Act & Assert
        assertThrows(ValidationException.class, () -> this.refreshTokenService.refreshAccessToken(expiredRequest));
        verify(this.refreshTokenRepository).findFirstByToken(expiredToken);
    }
}
