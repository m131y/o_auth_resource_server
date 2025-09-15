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

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/token")
    public ResponseEntity<TokenResponse> getToken(@RequestBody TokenRequest request) {
        Optional<User> optionalUser = userRepository.findByUsername(request.getUsername());
        if(optionalUser.isEmpty()) {
            return ResponseEntity.status(401).build();
        }

        User user = optionalUser.get();
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).build();
        }

        Set<String> requestedScopes = parseScope(request.getScope());
        Set<String> userScopes = user.getScopes().stream()
                .map(Scope::getValue)
                .collect(Collectors.toSet());

        Set<String> grantedScopes = requestedScopes.stream()
                .filter(userScopes::contains)
                .collect(Collectors.toSet());

        if (grantedScopes.isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getId(),
                grantedScopes
        );

        TokenResponse response = new TokenResponse(
                accessToken,
                "Bearer",
                3600,
                String.join(" ", grantedScopes)
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<String> getJwks() {
        return ResponseEntity.ok("{\"keys\":[]}");
    }

    private Set<String> parseScope(String scopeString) {
        if (scopeString == null || scopeString.trim().isEmpty()) {
            return new HashSet<>();
        }
        return Arrays.stream(scopeString.split("\\s+"))
                .collect(Collectors.toSet());
    }
}