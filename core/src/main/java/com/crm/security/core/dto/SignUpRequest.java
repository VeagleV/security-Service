package com.crm.security.core.dto;


import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Запрос на регистрацию")
public class SignUpRequest {

    @Size(min = 5, max = 64)
    @NotBlank
    private String login;

    @Size(min = 6, max = 255)
    @NotBlank
    private String password;

    @Size(max = 255)
    @NotBlank
    private String email;

}
