package com.nexus.infrastructure.security.crypto;

import com.nexus.infrastructure.config.properties.CryptoProperties;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.PersistenceException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AttributeEncryptionService {

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String ENCRYPTED_PREFIX = "enc:";
  private static final int GCM_TAG_LENGTH_BITS = 128;
  private static final int IV_LENGTH_BYTES = 12;

  private static volatile Delegate delegate;

  private final CryptoProperties cryptoProperties;

  @PostConstruct
  public void initialize() {
    delegate = new Delegate(cryptoProperties.enabled(), deriveKey(cryptoProperties.secret()));
  }

  public static String encrypt(String plainText) {
    if (plainText == null || plainText.isBlank()) {
      return plainText;
    }
    return currentDelegate().encrypt(plainText);
  }

  public static String decrypt(String cipherText) {
    if (cipherText == null || cipherText.isBlank()) {
      return cipherText;
    }
    return currentDelegate().decrypt(cipherText);
  }

  private static Delegate currentDelegate() {
    Delegate current = delegate;
    if (current == null) {
      throw new PersistenceException("Attribute encryption service is not initialized");
    }
    return current;
  }

  private static byte[] deriveKey(String secret) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(secret.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("Unable to derive encryption key", ex);
    }
  }

  private record Delegate(boolean enabled, byte[] key) {
    private String encrypt(String plainText) {
      if (!enabled || plainText.startsWith(ENCRYPTED_PREFIX)) {
        return plainText;
      }

      byte[] iv = new byte[IV_LENGTH_BYTES];
      new SecureRandom().nextBytes(iv);

      try {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
            Cipher.ENCRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] payload =
            ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array();
        return ENCRYPTED_PREFIX + Base64.getEncoder().encodeToString(payload);
      } catch (GeneralSecurityException ex) {
        throw new PersistenceException("Failed to encrypt attribute", ex);
      }
    }

    private String decrypt(String cipherText) {
      if (!enabled || !cipherText.startsWith(ENCRYPTED_PREFIX)) {
        return cipherText;
      }

      try {
        byte[] payload = Base64.getDecoder().decode(cipherText.substring(ENCRYPTED_PREFIX.length()));
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        buffer.get(iv);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
      } catch (GeneralSecurityException | IllegalArgumentException ex) {
        throw new PersistenceException("Failed to decrypt attribute", ex);
      }
    }
  }
}
