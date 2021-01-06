package ru.bitsouth.libs.springstellarauthstarter.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.stellar.sdk.*;
import org.stellar.sdk.xdr.DecoratedSignature;
import org.stellar.sdk.xdr.OperationType;
import org.stellar.sdk.xdr.TransactionEnvelope;
import org.stellar.sdk.xdr.XdrDataInputStream;
import ru.bitsouth.libs.springstellarauthstarter.configuration.StellarAuthConfigurationProperties;
import shadow.com.google.common.io.BaseEncoding;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

@Validated
@Slf4j
@RequiredArgsConstructor
@Service
public class StellarIntegrationService {
    private final StellarAuthConfigurationProperties properties;
    private final Account stellarAccount;
    private final KeyPair stellarServerKeyPair;

    public String getChallenge(String publicKey, String home_domain) {
        log.info("get challenge for account [{}] and home_domain [{}]", publicKey, home_domain);
        ManageDataOperation operation = getManageDataOperation(publicKey);
        Transaction transaction = getTransaction(operation);
        transaction.sign(stellarServerKeyPair);
        String base64challenge = transaction.toEnvelopeXdrBase64();
        log.info("challenge for account [{}] and home_domain [{}] was returned", publicKey, home_domain);
        log.debug("result: {}", base64challenge);
        return base64challenge;
    }

    public String getJwtToken(String transaction) {
        log.info("get jwt token for transaction");

        Transaction tx = getTx(transaction);

        Operation operation = tx.getOperations()[0];
        byte[] hash = tx.hash();
        List<DecoratedSignature> signatures = tx.getSignatures();

        if (!tx.getSourceAccount().equals(stellarAccount.getAccountId())) {
            throw new RuntimeException("Invalid source account.");
        }

        if (signatures.stream().anyMatch(x -> !stellarServerKeyPair.verify(hash, x.getSignature().getSignature()))) {
            throw new RuntimeException("Server signature is missing or invalid.");
        }

        long now = System.currentTimeMillis() / 1000L;
        if (
                !(
                        Objects.nonNull(tx.getTimeBounds()) &&
                                now > tx.getTimeBounds().getMinTime() &&
                                now < tx.getTimeBounds().getMaxTime()
                )
        ) {
            throw new RuntimeException("Challenge transaction expired.");
        }

        if (operation.toXdr().getBody().getDiscriminant() != OperationType.MANAGE_DATA) {
            throw new RuntimeException("Challenge has no manageData operation.");
        }

        if (!StringUtils.hasText(operation.getSourceAccount())) {
            throw new RuntimeException("Challenge has no source account.");
        }

        log.info("source: {}", operation.getSourceAccount());
        KeyPair clientKeyPair = KeyPair.fromAccountId(operation.getSourceAccount());

        if (signatures.stream().allMatch(x -> clientKeyPair.verify(hash, x.getSignature().getSignature()))) {
            throw new RuntimeException("Client signature is missing or invalid.");
        }

        String jwtToken = Jwts.builder()
                .setIssuer(properties.getEndpoint())
                .setSubject(operation.getSourceAccount())
                .setIssuedAt(toDate(now))
                .setExpiration(toDate(now + properties.getJwtTokenLifetime()))
                .setId(toHexString(hash))
                .signWith(SignatureAlgorithm.HS512, properties.getJwtTokenSecret())
                .compact();

        log.info("jwt token was returned");
        log.debug("jwt token: {}", jwtToken);

        return jwtToken;
    }

    private Transaction getTx(String transaction) {
        log.info("decode tx");
        log.debug("tx string: {}", transaction);

        BaseEncoding base64Encoding = BaseEncoding.base64();
        byte[] decoded = base64Encoding.decode(transaction);
        XdrDataInputStream xdrDataInputStream =
                new XdrDataInputStream(new ByteArrayInputStream(decoded));
        TransactionEnvelope envelope;
        try {
            envelope = TransactionEnvelope.decode(xdrDataInputStream);
        } catch (IOException e) {
            log.error("Can't decode tx", e);
            throw new RuntimeException(e);
        }
        log.debug("envelope: {}", envelope);

        Transaction tx = (Transaction) Transaction.fromEnvelopeXdr(envelope, Network.PUBLIC);
        log.info("tx was decoded");
        log.debug("transaction: {}", transaction);
        return tx;
    }

    private Date toDate(long now) {
        return Date.from(Instant.ofEpochSecond(now));
    }

    private String toHexString(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    private Transaction getTransaction(ManageDataOperation operation) {
        Transaction transaction = new Transaction.Builder(
                stellarAccount, Network.PUBLIC
        )
                .addOperation(operation)
                .addTimeBounds(TimeBounds.expiresAfter(properties.getChallengeExpireIn()))
                .setBaseFee(properties.getBaseFee())
                .build();
        log.debug("transaction: {}", transaction);
        return transaction;
    }

    private ManageDataOperation getManageDataOperation(String publicKey) {
        ManageDataOperation manageDataOperation = new ManageDataOperation.Builder(
                properties.getManageDataOperationName(),
                getRandomBytes()
        )
                .setSourceAccount(publicKey)
                .build();
        log.debug("operation: {}", manageDataOperation);
        return manageDataOperation;
    }

    private byte[] getRandomBytes() {
        byte[] byteArray = new byte[32];
        ThreadLocalRandom.current().nextBytes(byteArray);
        return byteArray;
    }

    public String getToml() {
        return "WEB_AUTH_ACCOUNT=\"" + stellarServerKeyPair.getAccountId() + "\"\n" +
                "WEB_AUTH_ENDPOINT=\"" + properties.getEndpoint() + "\"";
    }
}
