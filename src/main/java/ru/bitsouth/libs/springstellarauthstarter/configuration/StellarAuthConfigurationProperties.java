package ru.bitsouth.libs.springstellarauthstarter.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.lang.Nullable;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties("spring.stellar.auth")
public class StellarAuthConfigurationProperties {
    @Nullable
    private String serverPrivateKey = "";
    @NotNull
    private Long challengeExpireIn = 300L;
    @NotNull
    private Long invalidSequence = 0L;
    @NotNull
    private Integer baseFee = 100;
    @NotBlank
    private String endpoint = "http://localhost:8080/auth";
    @NotNull
    private Integer jwtTokenLifetime = 3600;
    @NotBlank
    private String jwtTokenSecret;
}
