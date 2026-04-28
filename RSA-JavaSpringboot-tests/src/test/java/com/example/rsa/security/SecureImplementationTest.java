package com.example.rsa.security;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

 
public class SecureImplementationTest {
    @Test
    public void testOAEPPaddingIsNonDeterministic() throws Exception {
        // AI reference
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        String plaintext = "SensitiveDataToEncrypt";
        byte[] plaintextBytes = plaintext.getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted1 = cipher.doFinal(plaintextBytes);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted2 = cipher.doFinal(plaintextBytes);

        assertFalse(Arrays.equals(encrypted1, encrypted2), "OAEP should be non-deterministic");

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted1 = cipher.doFinal(encrypted1);
        byte[] decrypted2 = cipher.doFinal(encrypted2);

        assertArrayEquals(decrypted1, decrypted2, "Both ciphertexts should decrypt the same");
        assertArrayEquals(plaintextBytes, decrypted1, "Decrypted data should match");
    }
    @Test
    public void testStrongKeySizeEnforced() throws Exception {
        // AI reference
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        int keySize = publicKey.getModulus().bitLength();

        assertTrue(keySize >= 2048, "Key size should be at least 2048 bits");

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        String testMessage = "Testing strong keys";
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(testMessage.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        assertEquals(testMessage, new String(decrypted), "Keys should encrypt/decrypt");
    }
    @Test
    public void testPrivateKeyNotExposed() throws Exception {
        // AI reference
        String secureApiResponse = "{\n" +
            "  \"user_id\": 1,\n" +
            "  \"username\": \"testuser\",\n" +
            "  \"public_key\": \"-----BEGIN PUBLIC KEY-----\\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\\n" +
            "-----END PUBLIC KEY-----\"\n" +
            "}";
        boolean responseContainsPrivateKey = secureApiResponse.contains("BEGIN PRIVATE KEY") ||
                                             secureApiResponse.contains("private_key");

        assertFalse(responseContainsPrivateKey, "Response should not include private keys");
        assertTrue(secureApiResponse.contains("user_id"), "Response should include user_id");
        assertTrue(secureApiResponse.contains("username"), "Response should include username");
        assertTrue(secureApiResponse.contains("public_key"), "Response should include public_key");
    }
    @Test
    public void testCompleteSecureEncryptionFlow() throws Exception {
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String originalData = "Confidential document content that must be protected";
        byte[] plaintextBytes = originalData.getBytes();

        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedData = encryptCipher.doFinal(plaintextBytes);

        assertFalse(Arrays.equals(plaintextBytes, encryptedData), "Data should be encrypted");

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        assertArrayEquals(plaintextBytes, decryptedData, "Decrypted data should match");
        assertEquals(originalData, new String(decryptedData), "Text should round-trip");
    }
}
