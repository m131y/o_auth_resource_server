package com.my131.o_auth_resource_server.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

@Service
public class JwtService {
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String issuer;
    private final long expiration;

    public JwtService(
            @Value("${jwt.private-key}") Resource privateKeyResource,
            @Value("${jwt.public-key}") Resource publicKeyResource,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.expiration}") long expiration
    ) throws Exception {
        this.privateKey = loadPrivateKey(privateKeyResource);
        this.publicKey = loadPublicKey(publicKeyResource);
        this.issuer = issuer;
        this.expiration = expiration;
    }

    // JWT를 만드는 메서드
    public String generateToken(String username, Long userId, Set<String> scopes) {
        try {
            Instant now = Instant.now();
            Instant expiryTime = now.plusSeconds(expiration);

            // claims 객체 생성
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(username)
                    .issuer(issuer)
                    .claim("userId", userId)
                    .claim("scope", String.join(" ", scopes))
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiryTime))
                    .build();

            // JWT의 뼈대를 만드는 역할
            // 토큰에 들어갈 헤더(Header)와 클레임 세트(Claims Set)를 정의하여 JWT 객체를 초기화
            SignedJWT signedJWT = new SignedJWT(
                    // JWSHeader: JWT의 헤더를 정의
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    claimsSet
            );

            // 개인키를 사용해 서명을 추가하여 최종적인 JWT 문자열을 완성
            signedJWT.sign(new RSASSASigner(privateKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("토큰 생성 실패", e);
        }
    }

    // 토큰 유효성 검증 메서드
    public boolean validateToken(String token) {
        try {
            // JWT 문자열을 파싱하여 SignedJWT 객체로 변환
            SignedJWT signedJWT = SignedJWT.parse(token);
            // verifier 객체 생성해 공개키 설정
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            // 공개 키 서명이 유효하지 않으면 false 반환
            if (!signedJWT.verify(verifier)) {
                return false;
            }

            // 유효하다면 만료 시간 검증
            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();

            return expirationTime.after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    // .pem 파일을 읽고 private 키 객체로 변환
    private RSAPrivateKey loadPrivateKey(Resource resource) throws Exception {
        String content = new String(Files.readAllBytes(resource.getFile().toPath()));
        String privateKeyPEM = content
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    // .pem 파일을 읽고 public 키 객체로 변환
    private RSAPublicKey loadPublicKey(Resource resource) throws Exception {
        String content = new String(Files.readAllBytes(resource.getFile().toPath()));
        String publicKeyPEM = content
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(spec);
    }
}