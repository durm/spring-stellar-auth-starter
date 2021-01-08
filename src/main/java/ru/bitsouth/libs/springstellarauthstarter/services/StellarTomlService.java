package ru.bitsouth.libs.springstellarauthstarter.services;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.stellar.sdk.KeyPair;
import ru.bitsouth.libs.springstellarauthstarter.configuration.StellarAuthConfigurationProperties;

import javax.validation.constraints.NotBlank;

@Validated
@Slf4j
@RequiredArgsConstructor
@Service
public class StellarTomlService {
    private final StellarAuthConfigurationProperties properties;
    private final KeyPair stellarServerKeyPair;

    public @NotBlank String getToml() {
        return "" +
                "SIGNING_KEY=\"" + stellarServerKeyPair.getAccountId() + "\"\n" +
                "WEB_AUTH_ENDPOINT=\"" + properties.getEndpoint() + "\"";
    }
}
