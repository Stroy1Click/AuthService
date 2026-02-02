package ru.stroy1click.auth.service;


import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.RefreshTokenRequest;

public interface AuthService {

    void createUser(UserDto userDto);

    String generateToken(String email);

    void logout(RefreshTokenRequest refreshTokenRequest);

    UserDto login(AuthRequest authRequest);
}
