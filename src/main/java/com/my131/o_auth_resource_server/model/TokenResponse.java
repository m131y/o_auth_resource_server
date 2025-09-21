package com.my131.o_auth_resource_server.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * 인증 서버(Authorization Server) 간의 통신에 사용되는 데이터 구조를 정의
 * 클라이언트(예: 모바일 앱)가 인증 서버의 토큰 발급 엔드포인트로 보내는 요청 데이터
 */
@Getter
@Setter
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String scope;
}