package com.crm.security.core.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class JwtAuthenticationResponse {
    @Schema(name = "Токен доступа")
    private String token;
}
