package ru.stroy1click.auth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.stroy1click.auth.client.UserClient;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.service.AuthService;
import ru.stroy1click.auth.service.RefreshTokenService;
import ru.stroy1click.common.exception.ValidationException;
import ru.stroy1click.common.service.JwtService;

import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserClient userClient;

    private final JwtService jwtService;

    private final RefreshTokenService refreshTokenService;

    private final PasswordEncoder passwordEncoder;

    private final MessageSource messageSource;

    @Override
    public void createUser(UserDto userDto) {
        log.info("createUser");

        this.userClient.create(userDto);
    }

    @Override
    public String generateToken(String email) {
        log.info("generate {}", email);
        UserDto user = this.userClient.getByEmail(email);

        return this.jwtService.generate(user.getEmail(), user.getRole().toString(), user.getEmailConfirmed());
    }

    @Override
    public void logout(RefreshTokenRequest refreshTokenRequest) {
        log.info("logout {}", refreshTokenRequest);

        this.refreshTokenService.delete(refreshTokenRequest.getRefreshToken());
    }

    @Override
    public UserDto login(AuthRequest authRequest) {
        log.info("login");
        UserDto userDto = this.userClient.getByEmail(authRequest.getEmail());

        if(this.passwordEncoder.matches(authRequest.getPassword(), userDto.getPassword())){
            return userDto;
        } else{
            throw new ValidationException(
                    this.messageSource.getMessage(
                            "error.password.incorrect",
                            null,
                            Locale.getDefault()
                    )
            );
        }
    }
}
