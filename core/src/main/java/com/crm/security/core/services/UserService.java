package com.crm.security.core.services;


import com.crm.security.core.entities.User;
import com.crm.security.core.enums.UserRoles;
import com.crm.security.core.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {


    private UserRepository userRepository;

    public User save(User user) {
        return userRepository.save(user);
    }


    public User createUser(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        return save(user);
    }


    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Username not found"));
    }


    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    public User getCurrentUser() {
        String username = null;
        try {
            username = SecurityContextHolder.getContext().getAuthentication().getName();
        } catch (Exception e) {
            throw new RuntimeException("No current user in the context");
        }

        return getByUsername(username);
    }


    public void getAdmin(){
        var user = getCurrentUser();
        user.setRole(UserRoles.ADMIN);
        save(user);
    }
}
