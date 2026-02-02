package ru.stroy1click.auth.unit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.MessageSource;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.exception.NotFoundException;
import ru.stroy1click.auth.exception.ValidationException;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.entity.RefreshToken;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.repository.RefreshTokenRepository;
import ru.stroy1click.auth.service.JwtService;
import ru.stroy1click.auth.service.impl.RefreshTokenServiceImpl;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenTest {

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
        MockitoAnnotations.openMocks(this);

        this.userDto = new UserDto();
        this.userDto.setId(1L);
        this.userDto.setEmail("test@example.com");

        this.refreshToken = new RefreshToken();
        this.refreshToken.setUserEmail("test@example.com");
        this.refreshToken.setToken("test-token");
        this.refreshToken.setExpiryDate(Instant.now().plusSeconds(600000));

        this.refreshTokenRequest = new RefreshTokenRequest();
        this.refreshTokenRequest.setRefreshToken("test-token");
    }

    @Test
    public void createRefreshToken_ShouldCreateToken_WhenUserExistsAndSessionsLessThanSix() {
        // Given
        when(this.refreshTokenRepository.countByUserEmail("test@example.com")).thenReturn(5);
        
        RefreshToken savedToken = RefreshToken.builder()
                .userEmail("test@example.com")
                .token("test-token")
                .expiryDate(Instant.now().plusSeconds(600000))
                .build();
        
        when(this.refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(savedToken);

        // When
        RefreshToken result = this.refreshTokenService.createRefreshToken("test@example.com");

        // Then
        assertNotNull(result);
        assertEquals(this.userDto.getEmail(), result.getUserEmail());
        verify(this.refreshTokenRepository).countByUserEmail("test@example.com");
        verify(this.refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    public void createRefreshToken_ShouldThrowValidationException_WhenUserHasMoreThanSixSessions() {
        // Given
        when(this.refreshTokenRepository.countByUserEmail("test@example.com")).thenReturn(7);

        // When & Then
        assertThrows(ValidationException.class, () -> this.refreshTokenService.createRefreshToken("test@example.com"));
        verify(this.refreshTokenRepository).countByUserEmail("test@example.com");
    }

    @Test
    public void findByToken_ShouldReturnToken_WhenTokenExists() {
        // Given
        when(this.refreshTokenRepository.findFirstByToken("test-token")).thenReturn(Optional.of(refreshToken));

        // When
        Optional<RefreshToken> result = this.refreshTokenService.findByToken("test-token");

        // Then
        assertTrue(result.isPresent());
        assertEquals(refreshToken, result.get());
        verify(this.refreshTokenRepository).findFirstByToken("test-token");
    }

    @Test
    public void findByToken_ShouldReturnEmptyOptional_WhenTokenNotExists() {
        // Given
        String token = "nonexistent-token";
        when(this.refreshTokenRepository.findFirstByToken(token)).thenReturn(Optional.empty());

        // When
        Optional<RefreshToken> result = this.refreshTokenService.findByToken(token);

        // Then
        assertFalse(result.isPresent());
        verify(this.refreshTokenRepository).findFirstByToken(token);
    }

    @Test
    public void delete_ShouldDeleteTokenByTokenString_WhenCalled() {
        // When
        this.refreshTokenService.delete("test-token");

        // Then
        verify(this.refreshTokenRepository).deleteByToken("test-token");
    }

    @Test
    public void deleteAll_ShouldDeleteAllTokensForUser_WhenCalled() {
        // When
        this.refreshTokenService.deleteAll("test@example.com");

        // Then
        verify(this.refreshTokenRepository).deleteAllByUserEmail("test@example.com");
    }

    @Test
    public void extendTheExpirationDate_ShouldExtendExpiration_WhenTokenExists() {
        // Given
        Instant oldExpiryDate = Instant.now();
        refreshToken.setExpiryDate(oldExpiryDate);
        when(this.refreshTokenRepository.findFirstByToken("test-token")).thenReturn(Optional.of(refreshToken));

        // When
        this.refreshTokenService.extendTheExpirationDate(refreshTokenRequest);

        // Then
        verify(this.refreshTokenRepository).findFirstByToken("test-token");
        verify(this.refreshTokenRepository).save(refreshToken);
        assertTrue(refreshToken.getExpiryDate().isAfter(oldExpiryDate));
    }

    @Test
    public void extendTheExpirationDate_ShouldThrowNotFoundException_WhenTokenNotExists() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("nonexistent-token");

        when(this.refreshTokenRepository.findFirstByToken("nonexistent-token")).thenReturn(Optional.empty());
        when(this.messageSource.getMessage("error.refresh.token.not_found", null, Locale.getDefault()))
                .thenReturn("Refresh token not found");

        // When & Then
        assertThrows(NotFoundException.class, () -> this.refreshTokenService.extendTheExpirationDate(request));
        verify(this.refreshTokenRepository).findFirstByToken("nonexistent-token");
    }

    @Test
    public void refreshAccessToken_ShouldReturnJwtResponse_WhenTokenExistsAndNotExpired() {
        // Given
        when(this.refreshTokenRepository.findFirstByToken("test-token")).thenReturn(Optional.of(refreshToken));
        when(this.jwtService.generate(userDto)).thenReturn("new access token");
        when(this.userClient.getByEmail(refreshToken.getUserEmail())).thenReturn(this.userDto);

        // When
        JwtResponse result = this.refreshTokenService.refreshAccessToken(this.refreshTokenRequest);

        // Then
        assertNotNull(result);
        assertEquals("new access token", result.getAccessToken());
        assertEquals("test-token", result.getRefreshToken());
        verify(this.refreshTokenRepository).findFirstByToken("test-token");
        verify(this.jwtService).generate(userDto);
    }

    @Test
    public void refreshAccessToken_ShouldThrowNotFoundException_WhenTokenNotExists() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("nonexistent-token");

        when(this.refreshTokenRepository.findFirstByToken("nonexistent-token")).thenReturn(Optional.empty());
        when(this.messageSource.getMessage("error.refresh.token.not_found", null, Locale.getDefault()))
                .thenReturn("Refresh token not found");

        // When & Then
        assertThrows(NotFoundException.class, () -> this.refreshTokenService.refreshAccessToken(request));
        verify(this.refreshTokenRepository).findFirstByToken("nonexistent-token");
    }

    @Test
    public void refreshAccessToken_ShouldThrowValidationException_WhenTokenExpired() {
        // Given
        String expiredToken = "expired-token";
        RefreshToken expiredRefreshToken = new RefreshToken();
        expiredRefreshToken.setUserEmail("test@example.com");
        expiredRefreshToken.setToken(expiredToken);
        expiredRefreshToken.setExpiryDate(Instant.now().minusSeconds(600000)); // Expired
        
        RefreshTokenRequest expiredRequest = new RefreshTokenRequest();
        expiredRequest.setRefreshToken(expiredToken);

        when(this.refreshTokenRepository.findFirstByToken(expiredToken)).thenReturn(Optional.of(expiredRefreshToken));
        when(this.messageSource.getMessage("error.refresh.token.expired", null, Locale.getDefault()))
                .thenReturn("Refresh token expired");

        // When & Then
        assertThrows(ValidationException.class, () -> this.refreshTokenService.refreshAccessToken(expiredRequest));
        verify(this.refreshTokenRepository).findFirstByToken(expiredToken);
    }
}
