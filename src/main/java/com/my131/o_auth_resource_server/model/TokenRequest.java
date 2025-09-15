package com.my131.o_auth_resource_server.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenRequest {
    private String username;
    private String password;
    private String scope;
}