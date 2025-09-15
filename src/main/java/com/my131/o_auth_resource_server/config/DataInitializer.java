package com.my131.o_auth_resource_server.config;

import com.my131.o_auth_resource_server.model.Role;
import com.my131.o_auth_resource_server.model.Scope;
import com.my131.o_auth_resource_server.model.User;
import com.my131.o_auth_resource_server.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("user").isEmpty()) {
                User user = new User();
                user.setUsername("user");
                user.setPassword(passwordEncoder.encode("password"));
                user.setRoles(Set.of(Role.USER));
                user.setScopes(Set.of(Scope.READ_USERS, Scope.READ_POSTS));
                userRepository.save(user);
            }

            if (userRepository.findByUsername("admin").isEmpty()) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode("password"));
                admin.setRoles(Set.of(Role.ADMIN));
                admin.setScopes(Set.of(Scope.ADMIN, Scope.READ_USERS, Scope.WRITE_USERS));
                userRepository.save(admin);
            }

            if (userRepository.findByUsername("user2").isEmpty()) {
                User user2 = new User();
                user2.setUsername("user2");
                user2.setPassword(passwordEncoder.encode("password"));
                user2.setRoles(Set.of(Role.USER));
                user2.setScopes(Set.of(Scope.READ_USERS, Scope.READ_POSTS));
                userRepository.save(user2);
            }
        };
    }
}