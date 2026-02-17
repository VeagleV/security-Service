package com.crm.security.core.repositories;

import com.crm.security.core.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String login);
    boolean existsByUsername(String login);
    boolean existsByEmail(String email);
}
