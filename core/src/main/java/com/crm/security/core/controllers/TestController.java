package com.crm.security.core.controllers;

import com.crm.security.core.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/example")
@RequiredArgsConstructor
@Tag(name = "ТЕСТ")
public class TestController {

    private final UserService service;

    @GetMapping
    @Operation(summary = "Доступен только авторизованным пользователям")
    public Mono<String> example() {
        return Mono.just("Hello, world!");
    }

    @GetMapping("/admin")
    @Operation(summary = "Доступен только пользователям с ролью ADMIN")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<String> exampleAdmin() {
        return Mono.just("Hello, admin!");
    }

    @GetMapping("/get-admin")
    @Operation(summary = "Получить роль ADMIN (для демонстрации)")
    public Mono<Void> getAdmin() {
        return Mono.fromRunnable(service::getAdmin);
    }

    @GetMapping("/get-super-admin")
    @Operation(summary = "Получить роль SUPER_ADMIN (для демонстрации)")
    public Mono<Void> getSuperAdmin() {
        return Mono.fromRunnable(service::getSuperAdmin);
    }

    @GetMapping("/super-admin")
    @Operation(summary = "Доступен только пользователям с ролью SUPER_ADMIN")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<String> exampleSuperAdmin() {
        return Mono.just("Hello, super admin!");
    }
}