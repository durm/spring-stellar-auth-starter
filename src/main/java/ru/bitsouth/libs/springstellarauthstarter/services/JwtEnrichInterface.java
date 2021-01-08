package ru.bitsouth.libs.springstellarauthstarter.services;

import io.jsonwebtoken.JwtBuilder;

public interface JwtEnrichInterface {
    void enrich(JwtBuilder jwtBuilder, String publicKey);
}
