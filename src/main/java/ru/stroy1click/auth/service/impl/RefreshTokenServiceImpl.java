package ru.stroy1click.auth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.entity.RefreshToken;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.repository.RefreshTokenRepository;
import ru.stroy1click.auth.service.RefreshTokenService;
import ru.stroy1click.common.exception.NotFoundException;
import ru.stroy1click.common.exception.ValidationException;
import ru.stroy1click.common.service.JwtService;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final UserClient userClient;

    private final MessageSource messageSource;

    private final JwtService jwtService;

    /**
     * Создает новый refresh токен для пользователя, идентифицируемого по email. Если у пользователя
     * более 6 активных сессий, выбрасывает исключение валидации.
     */
    @Override
    public RefreshToken createRefreshToken(String email) {
        log.info("createRefreshToken {}", email);

        RefreshToken refreshToken = RefreshToken.builder()
                .userEmail(email)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusSeconds(Duration.ofDays(14).toSeconds()))
                .build();

        if(this.refreshTokenRepository.countByUserEmail(email) <= 6){
            return this.refreshTokenRepository.save(refreshToken);
        } else {
            throw new ValidationException(
                    this.messageSource.getMessage(
                            "error.refresh_token.max_session",
                            null,
                            Locale.getDefault()
                    )
            );
        }
    }

    @Override
    public void delete(String token) {
        log.info("delete {}", token);

        RefreshToken foundToken  = this.refreshTokenRepository.findFirstByToken(token).orElseThrow(
                        () -> new NotFoundException(
                                this.messageSource.getMessage("error.refresh_token.not_found",
                                        new Object[]{token},
                                        Locale.getDefault())
                        )
                );

        this.refreshTokenRepository.delete(foundToken);
    }

    @Override
    public void deleteAll(String email) {
        log.info("deleteAll for user with {} id", email);

        this.refreshTokenRepository.deleteAllByUserEmail(email);
    }

    @Override
    public void extendTheExpirationDate(RefreshTokenRequest request) {
        log.info("extendTheExpirationDate");

        RefreshToken refreshToken = this.refreshTokenRepository.findFirstByToken(request.getRefreshToken())
                        .orElseThrow(
                                () -> new NotFoundException(
                                        this.messageSource.getMessage("error.refresh_token.not_found",
                                                new Object[]{request.getRefreshToken()},
                                                Locale.getDefault())
                                )
                        );

        refreshToken.setExpiryDate(refreshToken.getExpiryDate()
                .plus(Duration.ofDays(7)));
    }

    @Override
    public JwtResponse refreshAccessToken(RefreshTokenRequest request) {
        log.info("refreshAccessToken {}", request);

        RefreshToken refreshToken = this.refreshTokenRepository.findFirstByToken(request.getRefreshToken())
                .orElseThrow(
                        () -> new NotFoundException(
                                this.messageSource.getMessage(
                                        "error.refresh_token.not_found",
                                        new Object[]{request.getRefreshToken()},
                                        Locale.getDefault()
                                )
                        )
                );

        verifyExpiration(refreshToken);

        UserDto userDto = this.userClient.getByEmail(refreshToken.getUserEmail());

        return JwtResponse.builder()
                .accessToken(this.jwtService.generate(userDto.getEmail(),
                        userDto.getRole().toString(), userDto.getIsEmailConfirmed()))
                .refreshToken(refreshToken.getToken())
                .build();
    }

    @Override
    public void deleteAllExpiredTokens() {
        List<RefreshToken> expiredTokens = this.refreshTokenRepository.findAllExpiredTokens();

        if(!expiredTokens.isEmpty()){
            log.info("deleteAllExpiredTokens");
            this.refreshTokenRepository.deleteAll(expiredTokens);
        }
    }

    private void verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            throw new ValidationException(
                    this.messageSource.getMessage(
                            "error.refresh_token.expired",
                            null,
                            Locale.getDefault()
                    )
            );
        }
    }

}