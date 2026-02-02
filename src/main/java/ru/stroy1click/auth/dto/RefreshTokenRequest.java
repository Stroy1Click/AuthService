package ru.stroy1click.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenRequest {

    @Length(min = 36, max = 36, message = "{validation.refresh.token.request.refresh_token.length}")
    @NotBlank(message = "{validation.refresh.token.request.refresh_token.not_blank}")
    private String refreshToken;

}