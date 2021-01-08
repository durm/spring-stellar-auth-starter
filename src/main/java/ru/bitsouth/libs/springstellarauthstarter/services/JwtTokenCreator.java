package ru.bitsouth.libs.springstellarauthstarter.services;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import ru.bitsouth.libs.springstellarauthstarter.configuration.StellarAuthConfigurationProperties;

import javax.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@Slf4j
@Validated
@RequiredArgsConstructor
public class JwtTokenCreator {
    private final StellarAuthConfigurationProperties properties;
    private final List<JwtEnrichInterface> enriches;

    public @NotBlank String issue(@NotBlank String publicKey, @NotBlank String txHash) {
        log.info("issue jwt token for [{}]", publicKey);
        log.debug("tx: {}", txHash);

        long now = System.currentTimeMillis() / 1000L;

        JwtBuilder jwtBuilder = Jwts.builder()
                .setIssuer(properties.getEndpoint())
                .setSubject(publicKey)
                .setIssuedAt(toDate(now))
                .setExpiration(toDate(now + properties.getJwtTokenLifetime()))
                .setId(txHash)
                .signWith(SignatureAlgorithm.HS512, properties.getJwtTokenSecret());

        enriches.forEach(x -> {
            log.debug("add custom claims: {}", x);
            x.enrich(jwtBuilder, publicKey);
        });

        String token = jwtBuilder.compact();

        log.info("jwt token was issued for [{}]", publicKey);
        log.debug("token: {}", token);
        return token;
    }

    private Date toDate(long now) {
        return Date.from(Instant.ofEpochSecond(now));
    }
}
