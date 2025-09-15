package com.my131.o_auth_resource_server.resource;

import com.my131.o_auth_resource_server.model.User;
import com.my131.o_auth_resource_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {
    private final UserRepository userRepository;
    private final ScopeChecker scopeChecker;

    @GetMapping("/users/me")
    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    public ResponseEntity<Map<String, Object>> getCurrent(Authentication authentication) {
        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
        Jwt jwt = jwtAuth.getToken();

        assert jwt.getIssuedAt() != null;
        assert jwt.getExpiresAt() != null;
        return ResponseEntity.ok(Map.of("username", jwt.getSubject(),
                "userId", jwt.getClaimAsString("userId"),
                "scopes", jwt.getClaimAsString("scope"),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt())
        );
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{userId}")
    @PreAuthorize("@scopeChecker.canAccessUser(#userId)")
    public ResponseEntity<User> getUser(@PathVariable Long userId) {
        Optional<User> user = userRepository.findById(userId);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/admin/stats")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, Object>> getAdminStats() {
        long totalUsers = userRepository.count();

        return ResponseEntity.ok(Map.of(
                "totalUsers", totalUsers,
                "timestamp", Instant.now(),
                "message", "관리자 전용 통계 정보"
        ));
    }
}