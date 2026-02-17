package com.crm.security.core.entities;

import com.crm.security.core.enums.UserRoles;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


@Entity
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "user")
public class User implements UserDetails {

        @Id
        @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_id_seq")
        @SequenceGenerator(name = "user_id_seq", sequenceName = "user_id_seq", allocationSize = 1)
        @Column(name = "user_id")
        private Long id;

        @Column(unique = true, nullable = false)
        private String username;

        @Column(name = "password_hash", nullable = false)
        private String password;

        @Column(unique = true, nullable = false)
        private String email;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false)
        private UserRoles role;

        @Column(nullable = false)
        private String fio;


        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
                return List.of( new SimpleGrantedAuthority(role.name()));
        }

        @Override
        public String getUsername() {
                return username;
        }

        @Override
        public String getPassword() {
                return password;
        }

        @Override
        public boolean isAccountNonExpired() {
                return true;
        }

        @Override
        public boolean isAccountNonLocked() {
                return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
                return true;
        }

        @Override
        public boolean isEnabled() {
                return true;
        }
}
