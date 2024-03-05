package com.example.icon;

import foundation.icon.icx.KeyWallet;
import foundation.icon.icx.SignedTransaction;
import foundation.icon.icx.Transaction;
import foundation.icon.icx.TransactionBuilder;
import foundation.icon.icx.crypto.ECDSASignature;
import foundation.icon.icx.data.Address;
import foundation.icon.icx.data.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;


@Slf4j
public class IconTest {

    private final String serializedTransaction
            = "icx_sendTransaction.from.hx8a2c51300334d7791cf8377ae42b721f537a4e01.nid.0x1.nonce.0x1.stepLimit.0x186a0.timestamp.0x6123ef33545b8.to.hxb678bd32e86308fdc05bf44fe005c0c935dbaba2.value.0x3e8.version.0x3";
    private final BigInteger key = new BigInteger("64186588625296304500275520245867802253924063285282458200975891251650071368419");

    @Test
    public void sign() {
        final String sdkSignature = getSdkSignature();
        final String signature = getSignature();

        Assertions.assertThat(sdkSignature).isEqualTo(signature);
    }

    private String getSdkSignature() {
        final Bytes privateKey = new Bytes(BigIntegers.asUnsignedByteArray(32, key));
        KeyWallet keyWallet = KeyWallet.load(privateKey);

        final BigInteger networkId = new BigInteger("1");
        final String from = "hx8a2c51300334d7791cf8377ae42b721f537a4e01";
        final String to = "hxb678bd32e86308fdc05bf44fe005c0c935dbaba2";
        final BigInteger value = BigInteger.valueOf(1000);
        final BigInteger nonce = BigInteger.valueOf(1);
        final BigInteger stepLimit = BigInteger.valueOf(100000);
        final BigInteger timestamp = new BigInteger("1708911437891000");

        Transaction transaction = TransactionBuilder.newBuilder()
                .nid(networkId)
                .from(new Address(from))
                .to(new Address(to))
                .value(value)
                .stepLimit(stepLimit)
                .timestamp(timestamp)
                .nonce(nonce)
                .build();

        SignedTransaction signedTransaction = new SignedTransaction(transaction, keyWallet);

        String sdkSignature = signedTransaction.getProperties().getItem("signature").asString();
        log.info("sdkSignature = {}", sdkSignature);
        return sdkSignature;
    }

    private String getSignature() {
        final Bytes privateKey = new Bytes(BigIntegers.asUnsignedByteArray(32, key));
        ECDSASignature ecdsaSignature = new ECDSASignature(privateKey);
        byte[] data = new SHA3.Digest256().digest(serializedTransaction.getBytes(StandardCharsets.UTF_8));
        BigInteger[] sig = ecdsaSignature.generateSignature(data);
        byte[] signatureBytes = ecdsaSignature.recoverableSerialize(sig, data);
        String signature = Base64.toBase64String(signatureBytes);
        log.info("signature = {}", signature);
        return signature;
    }

    @Test
    public void serialize() {
        final String signature = getSignature();

        // serialize
        ByteBuffer buffer = ByteBuffer.allocate(serializedTransaction.length() + signature.length());
        buffer.put(serializedTransaction.getBytes());
        buffer.put(signature.getBytes());
        byte[] serializedSignedRawTx = buffer.array();

        // deserialize
        ByteBuffer slice = ByteBuffer.wrap(serializedSignedRawTx).slice();
        int size = slice.limit() - serializedTransaction.length();
        byte[] rawTransaction = new byte[serializedTransaction.length()];
        byte[] rawSignature = new byte[size];
        slice.get(rawTransaction);
        slice.get(rawSignature);

        String deserializedRawTransaction = new String(rawTransaction).trim();
        String deserializedSignature = new String(rawSignature);

        Assertions.assertThat(deserializedRawTransaction).isEqualTo(serializedTransaction);
        Assertions.assertThat(deserializedSignature).isEqualTo(signature);
    }

}
