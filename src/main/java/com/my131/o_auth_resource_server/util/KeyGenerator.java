package com.my131.o_auth_resource_server.util;

import lombok.extern.slf4j.Slf4j;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Slf4j
public class KeyGenerator {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String privateKeyContent = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n" +
                "-----END PRIVATE KEY-----";

        writeToFile("src/main/resources/private.pem", privateKeyContent);

        String publicKeyContent = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" +
                "-----END PUBLIC KEY-----";

        writeToFile("src/main/resources/public.pem", publicKeyContent);

        log.info("키 파일들이 생성되었습니다:");
        log.info("- src/main/resources/private.pem");
        log.info("- src/main/resources/public.pem");
    }

    private static void writeToFile(String filename, String content) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(content);
        }
    }
}
