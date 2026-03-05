package com.crm.security.core.services;

import com.crm.security.core.dto.JwtAuthenticationResponse;
import com.crm.security.core.dto.SignInRequest;
import com.crm.security.core.dto.SignUpRequest;
import com.crm.security.core.entities.User;
import com.crm.security.core.enums.UserRoles;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public Mono<JwtAuthenticationResponse> signUp(SignUpRequest request) {
        return Mono.fromCallable(() -> {
            var user = User.builder()
                    .username(request.getUsername())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .fio(request.getFio())
                    .role(UserRoles.MANAGER) // роль по умолчанию
                    .build();

            userService.createUser(user);

            var jwt = jwtService.generateToken(user);
            return new JwtAuthenticationResponse(jwt);
        });
    }

    public Mono<JwtAuthenticationResponse> signIn(SignInRequest request) {
        return Mono.fromCallable(() -> {
            User user = userService.getByUsername(request.getUsername());

            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new RuntimeException("Invalid username or password");
            }

            var jwt = jwtService.generateToken(user);
            return new JwtAuthenticationResponse(jwt);
        });
    }
}