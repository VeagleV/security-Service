package com.crm.security.core.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(name = "Запрос на аутентификацию")
public class SignInRequest {

    @Size(min = 5, max = 64)
    @NotBlank
    private String username;

    @Size(min = 6, max = 255)
    @NotBlank
    private String password;
}
