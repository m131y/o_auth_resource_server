package com.my131.o_auth_resource_server.model;

import lombok.Getter;
import lombok.Setter;

/**
 * 인증 서버(Authorization Server) 간의 통신에 사용되는 데이터 구조를 정의
 * 인증 서버가 클라이언트에게 다시 보내는 응답 데이터
 */
@Getter
@Setter
public class TokenRequest {
    private String username;
    private String password;
    private String scope;
}