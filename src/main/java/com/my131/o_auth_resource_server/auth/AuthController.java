package com.my131.o_auth_resource_server.auth;

import com.my131.o_auth_resource_server.model.Scope;
import com.my131.o_auth_resource_server.model.TokenRequest;
import com.my131.o_auth_resource_server.model.TokenResponse;
import com.my131.o_auth_resource_server.model.User;
import com.my131.o_auth_resource_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 인증 서버(Authorization Server) 컨트롤러
 * 클라이언트의 인증 요청을 처리
 * JWT 토큰을 발급
 */
@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/token")
    // request = username, password, scopes
    // user = id, username, password, roles, scopes
    public ResponseEntity<TokenResponse> getToken(@RequestBody TokenRequest request) {
        // request 정보로 user 검색
        Optional<User> optionalUser = userRepository.findByUsername(request.getUsername());
        // 없으면 401 오류 반환
        if(optionalUser.isEmpty()) {
            return ResponseEntity.status(401).build();
        }

        // Optional 객체에서 내부의 User 객체를 꺼내는 역할
        User user = optionalUser.get();
        // 패스워드 일치 확인
        // 틀리면 401 오류 반환
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).build();
        }

        // requestedScopes = 요청한 권한, userScopes 사용자가 가지고 있는 권한
        Set<String> requestedScopes = parseScope(request.getScope());
        Set<String> userScopes = user.getScopes().stream()
                .map(Scope::getValue)
                .collect(Collectors.toSet());

        // 요청한 스코프(권한) 중에서 사용자가 실제로 가진 스코프만 필터링하여 grantedScopes에 저장
        Set<String> grantedScopes = requestedScopes.stream()
                // = scope -> userScopes.contains(scope)
                .filter(userScopes::contains)
                .collect(Collectors.toSet());

        // grantedScopes에 가 비었으면 403 오류 반환
        if (grantedScopes.isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        // JWT accessToken 생성
        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getId(),
                grantedScopes
        );

        // 토큰 응답 생성
        TokenResponse response = new TokenResponse(
                accessToken,
                "Bearer",
                3600,
                String.join(" ", grantedScopes)
        );

        return ResponseEntity.ok(response);
    }

    // JWK Set (JWT 서명 검증에 필요한 공개 키 세트)를 제공
    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<String> getJwks() {
        return ResponseEntity.ok("{\"keys\":[]}");
    }

    // 권한 검증 후 set 형태로 반환
    private Set<String> parseScope(String scopeString) {
        if (scopeString == null || scopeString.trim().isEmpty()) {
            return new HashSet<>();
        }
        return Arrays.stream(scopeString.split("\\s+"))
                .collect(Collectors.toSet());
    }
}