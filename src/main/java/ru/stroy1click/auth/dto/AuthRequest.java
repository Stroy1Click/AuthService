package ru.stroy1click.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthRequest {

    @NotBlank(message = "{validation.auth.request.email.not_blank}")
    @Email(message = "{validation.auth.request.email.valid}")
    @Length(min = 8, max = 50, message = "{validation.auth.request.email.length}")
    private String email;

    @NotBlank(message = "{validation.auth.request.password.not_blank}")
    @Length(min = 8, max = 60, message = "{validation.auth.request.password.length}")
    private String password;

}