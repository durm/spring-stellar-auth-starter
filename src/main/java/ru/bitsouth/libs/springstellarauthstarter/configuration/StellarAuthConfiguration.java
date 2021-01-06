package ru.bitsouth.libs.springstellarauthstarter.configuration;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.stellar.sdk.Account;
import org.stellar.sdk.KeyPair;

@EnableConfigurationProperties(StellarAuthConfigurationProperties.class)
@Configuration
public class StellarAuthConfiguration {
    @Bean
    public KeyPair stellarServerKeyPair(StellarAuthConfigurationProperties properties) {
        if (StringUtils.hasText(properties.getServerPrivateKey())) {
            return KeyPair.fromSecretSeed(properties.getServerPrivateKey());
        }
        return KeyPair.random();
    }

    @Bean
    public Account stellarAccount(KeyPair stellarServerKeyPair, StellarAuthConfigurationProperties properties) {
        return new Account(stellarServerKeyPair.getAccountId(), properties.getInvalidSequence());
    }
}
