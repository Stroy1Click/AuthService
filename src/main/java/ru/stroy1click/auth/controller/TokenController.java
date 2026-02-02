package ru.stroy1click.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.stroy1click.auth.exception.ValidationException;
import ru.stroy1click.auth.dto.JwtResponse;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.service.RefreshTokenService;
import ru.stroy1click.auth.util.ValidationErrorUtils;

import java.util.Locale;

@RestController
@RequestMapping("/api/v1/tokens")
@RequiredArgsConstructor
public class TokenController {

    private final RefreshTokenService refreshTokenService;

    private final MessageSource messageSource;

    @PostMapping("/access")
    @Operation(summary = "Обновить access token")
    public ResponseEntity<JwtResponse> refreshAccessToken(@RequestBody @Valid RefreshTokenRequest refreshTokenRequest,
                                                    BindingResult bindingResult) {
        if(bindingResult.hasFieldErrors()) throw new ValidationException(
                ValidationErrorUtils.collectErrorsToString(bindingResult.getFieldErrors())
        );

        return ResponseEntity.ok(this.refreshTokenService.refreshAccessToken(refreshTokenRequest));
    }

    @PatchMapping("/refresh-token")
    @Operation(summary = "Обновить refresh token")
    public ResponseEntity<String> extendTheExpirationDate(@RequestBody @Valid RefreshTokenRequest refreshTokenRequest,
                                                          BindingResult bindingResult){
        if(bindingResult.hasFieldErrors()) throw new ValidationException(
                ValidationErrorUtils.collectErrorsToString(bindingResult.getFieldErrors())
        );

        this.refreshTokenService.extendTheExpirationDate(refreshTokenRequest);
        return ResponseEntity.ok(
                this.messageSource.getMessage(
                        "info.refresh.token.extend",
                        null,
                        Locale.getDefault()
                )
        );
    }
}
