package com.nexus.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.crypto")
public record CryptoProperties(boolean enabled, String secret) {
  public CryptoProperties {
    secret =
        (secret == null || secret.isBlank()) ? "default-test-and-dev-secret-change-me" : secret;
  }
}
