package com.crm.security.core.filters;


import com.crm.security.core.services.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import java.util.Map;

@Component("authComponentFilter")
@RequiredArgsConstructor
public class AuthHeaderFilter extends AbstractGatewayFilterFactory<AuthHeaderFilter.Config> {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public static class Config {

        private boolean optional = false;

        public boolean isOptional() {
            return optional;
        }

        public void setOptional(boolean optional) {
            this.optional = optional;
        }
    }

    @Override
    public Config newConfig() {
        return new Config();
    }


    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (StringUtils.isBlank(authHeader) || !authHeader.startsWith(BEARER_PREFIX)) {
                if (config.isOptional()) {
                    return chain.filter(exchange);
                }
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing Bearer token");
            }

            String jwt = authHeader.substring(BEARER_PREFIX.length());

            if (!jwtService.isTokenValidForGateway(jwt)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT");
            }

            Claims claims = jwtService.getClaims(jwt);
            Map<String, String> headersToAdd = jwtService.buildGatewayHeaders(claims);

            ServerWebExchange mutated = exchange.mutate()
                    .request(builder -> {
                        // чистим то, что мог подсунуть клиент
                        builder.headers(h -> {
                            h.remove("X-User-Id");
                            h.remove("X-User-Name");
                            h.remove("X-User-Role");
                        });

                        // добавляем “доверенные” заголовки
                        headersToAdd.forEach(builder::header);
                    })
                    .build();

            return chain.filter(mutated);
        };
    }

}