package com.example.icon;

import foundation.icon.icx.crypto.ECDSASignature;
import foundation.icon.icx.data.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;


@Slf4j
public class IconTest {

    private final String serializedTransaction
            = "icx_sendTransaction.from.hx8a2c51300334d7791cf8377ae42b721f537a4e01.nid.0x1.stepLimit.0x186a0.timestamp.0x6122fc2e490d0.to.hxb678bd32e86308fdc05bf44fe005c0c935dbaba2.value.0x3e8.version.0x3";
    private final String Signature = "LrQs9sAd6BCcP+lJ5DSylZwZd6YZxOywIKR7GviUMeRKN9ndAZawPRHrxVEwjngLlMvs0OYQI1Bo5Q/QZXuW7gA=";

    private final String exSerializedTransaction
            = "icx_sendTransaction.from.hxbe258ceb872e08851f1f59694dac2558708ece11.nid.0x1.stepLimit.0x12345.timestamp.0x563a6cf330136.to.cxb0776ee37f5b45bfaea8cff1d8232fbb6122ec32.value.0xde0b6b3a7640000.version.0x3";
    private final String exPrivateKey = "b'\\x870\\x91*\\xef\\xedB\\xac\\x05\\x8f\\xd3\\xf6\\xfdvu8\\x11\\x04\\xd49\\xb3\\xe1\\x1f\\x17\\x1fTR\\xd4\\xf9\\x19mL'";

    @Test
    public void test() {
        Bytes privateKey = new Bytes(exPrivateKey.getBytes()); // length 맞추기
        log.info("privateKey = {}", privateKey);

        ECDSASignature ecdsaSignature = new ECDSASignature(privateKey);
        byte[] data = new SHA3.Digest256().digest(exSerializedTransaction.getBytes(StandardCharsets.UTF_8));
        BigInteger[] sig = ecdsaSignature.generateSignature(data);
        byte[] signatureBytes = ecdsaSignature.recoverableSerialize(sig, data);
        String signature = Base64.toBase64String(signatureBytes);
        log.info("signature = {}", signature);
    }
}
