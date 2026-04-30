package com.nexus.infrastructure.security.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class AttributeHashingService {

  private AttributeHashingService() {}

  public static String sha256(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }

    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("Unable to hash attribute", ex);
    }
  }
}
