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

/**
 * 리소스 서버(Resource Server)  REST 컨트롤러
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {
    private final UserRepository userRepository;
    private final ScopeChecker scopeChecker;

    // 인증된 사용자의 토큰 정보를 반환
    @GetMapping("/users/me")
    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    public ResponseEntity<Map<String, Object>> getCurrent(Authentication authentication) {
        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
        Jwt jwt = jwtAuth.getToken();

        // JWT의 발행 시간(IssuedAt), getExpiresAt()이 null이 아니라고 가정하고, 만약 null 이면 오류를 발생
        assert jwt.getIssuedAt() != null;
        assert jwt.getExpiresAt() != null;
        // Map 형태로 토큰 정보 반환
        return ResponseEntity.ok(Map.of("username", jwt.getSubject(),
                "userId", jwt.getClaimAsString("userId"),
                "scopes", jwt.getClaimAsString("scope"),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt())
        );
    }

    // 모든 사용자 목록 조회
    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

    // 특정 사용자의 데이터를 ID로 조회 (본인, 관리자 허용)
    @GetMapping("/users/{userId}")
    @PreAuthorize("@scopeChecker.canAccessUser(#userId)")
    public ResponseEntity<User> getUser(@PathVariable Long userId) {
        Optional<User> user = userRepository.findById(userId);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // 관리자 전용 통계 조회
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

    // 수신된 JWT의 상세 정보를 확인
    @GetMapping("/token/info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();

            return ResponseEntity.ok(Map.of(
                    "tokenType", "JWT",
                    "subject", jwt.getSubject(),
                    "issuer", jwt.getIssuer(),
                    "issuedAt", jwt.getIssuedAt(),
                    "expiresAt", jwt.getExpiresAt(),
                    "scopes", jwt.getClaimAsString("scope"),
                    "authorities", authentication.getAuthorities()
            ));
        }
        return ResponseEntity.ok(Map.of("authenticated", false));
    }
}