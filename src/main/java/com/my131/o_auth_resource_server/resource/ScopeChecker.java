package com.my131.o_auth_resource_server.resource;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/**
 *  JWT 기반 리소스 서버의 접근 제어 로직을 구현
 *  세밀한 권한 검사를 수행
 */
@Component
public class ScopeChecker {
    // 접근 권한 확인
    public boolean canAccessUser(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // auth 가 JwtAuthenticationToken 타입이면, 그걸 jwtAuth 라는 변수로 캐스팅해서 사용
        if(!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            return false;
        }
        // jwtAuth.getToken = Spring Security가 SecurityContext에 넣어준 인증 객체에서 JWT 원본을 꺼냄
        Jwt jwt = jwtAuth.getToken();

        // 관리자 스코프 있으면 무조건 허용
        if (hasScope(auth, "admin")) {
            return true;
        }

        // read:users 스코프 있으면 "본인"만 허용
        if (hasScope(auth, "read:users")) {
            String tokenUserId = jwt.getClaimAsString("userId");
            return userId.toString().equals(tokenUserId);
        }

        // 그 외에는 접근 불가
        return false;
    }

    // 전체 사용자 수정 권한 확인
    public boolean canModifyUser(Long userId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        return hasScope(auth, "admin") || hasScope(auth, "write:users");
    }

    // 권한 검사
    private boolean hasScope(Authentication auth, String scope) {
        return auth.getAuthorities().stream().anyMatch(
                a -> a.getAuthority().equals("SCOPE_" + scope)
        );
    }
}