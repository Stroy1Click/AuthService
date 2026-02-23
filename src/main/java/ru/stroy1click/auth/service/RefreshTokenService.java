package ru.stroy1click.auth.service;


import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.entity.RefreshToken;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(String email);

    void delete(String token);

    void deleteAll(String email);

    void extendTheExpirationDate(RefreshTokenRequest request);

    JwtResponse refreshAccessToken(RefreshTokenRequest request);

    void deleteAllExpiredTokens();
}
