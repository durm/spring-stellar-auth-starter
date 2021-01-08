package ru.bitsouth.libs.springstellarauthstarter.services;

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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

@Validated
@Slf4j
@RequiredArgsConstructor
@Service
public class StellarAuthService {
    private final StellarAuthConfigurationProperties properties;
    private final Account stellarAccount;
    private final KeyPair stellarServerKeyPair;
    private final JwtTokenCreator jwtTokenCreator;

    public String getChallenge(String publicKey, String homeDomain) {
        log.info("get challenge for account [{}] and home_domain [{}]", publicKey, homeDomain);

        throwIfWrongHomeDomain(homeDomain);

        ManageDataOperation operation = getManageDataOperation(publicKey, homeDomain, getRandomBytes());
        Transaction transaction = getTransaction(operation);
        transaction.sign(stellarServerKeyPair);
        String base64challenge = transaction.toEnvelopeXdrBase64();

        log.info("challenge for account [{}] and home_domain [{}] was returned", publicKey, homeDomain);
        log.debug("result: {}", base64challenge);
        return base64challenge;
    }

    private void throwIfWrongHomeDomain(String homeDomain) {
        if (!homeDomain.endsWith(" auth")) {
            throw new RuntimeException("Wrong home domain.");
        }
    }

    public String getJwtToken(String transaction) {
        log.info("get jwt token for transaction");

        Transaction tx = getTx(transaction);

        Operation operation = tx.getOperations()[0];
        byte[] hash = tx.hash();
        List<DecoratedSignature> signatures = tx.getSignatures();

        throwIfInvalidSource(tx);
        throwIfServerSignatureIsWrong(hash, signatures);
        throwIfChallengeIsExpired(tx);
        throwIfThereIsNoManageData(operation);
        throwIfChallengeHasNoSourceAccount(operation);
        throwIfClientSignatureIsWrong(operation, hash, signatures);

        return jwtTokenCreator.issue(operation.getSourceAccount(), Util.bytesToHex(hash));
    }

    private void throwIfClientSignatureIsWrong(Operation operation, byte[] hash, List<DecoratedSignature> signatures) {
        KeyPair clientKeyPair = KeyPair.fromAccountId(operation.getSourceAccount());
        if (signatures.stream().allMatch(x -> clientKeyPair.verify(hash, x.getSignature().getSignature()))) {
            throw new RuntimeException("Client signature is missing or invalid.");
        }
    }

    private void throwIfChallengeHasNoSourceAccount(Operation operation) {
        if (!StringUtils.hasText(operation.getSourceAccount())) {
            throw new RuntimeException("Challenge has no source account.");
        }
    }

    private void throwIfThereIsNoManageData(Operation operation) {
        if (operation.toXdr().getBody().getDiscriminant() != OperationType.MANAGE_DATA) {
            throw new RuntimeException("Challenge has no manageData operation.");
        }
    }

    private void throwIfChallengeIsExpired(Transaction tx) {
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
    }

    private void throwIfServerSignatureIsWrong(byte[] hash, List<DecoratedSignature> signatures) {
        if (signatures.stream().anyMatch(x -> !stellarServerKeyPair.verify(hash, x.getSignature().getSignature()))) {
            throw new RuntimeException("Server signature is missing or invalid.");
        }
    }

    private void throwIfInvalidSource(Transaction tx) {
        if (!tx.getSourceAccount().equals(stellarAccount.getAccountId())) {
            throw new RuntimeException("Invalid source account.");
        }
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

    private ManageDataOperation getManageDataOperation(String publicKey, String name, byte[] value) {
        ManageDataOperation manageDataOperation = new ManageDataOperation.Builder(name, value)
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

}
