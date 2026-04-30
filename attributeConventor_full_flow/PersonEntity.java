package com.nexus.infrastructure.persistence.person;

import com.nexus.infrastructure.security.crypto.AttributeHashingService;
import com.nexus.infrastructure.persistence.account.AccountEntity;
import com.nexus.infrastructure.security.crypto.EncryptedStringAttributeConverter;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.*;

@Getter
@Setter
@Entity
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "person")
public class PersonEntity {

  @Id
  @Column(name = "person_id")
  private String personId;

  @OneToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "account_id", nullable = false, unique = true)
  private AccountEntity account;

  @Column(name = "first_name", nullable = false)
  @Convert(converter = EncryptedStringAttributeConverter.class)
  private String firstName;

  @Column(name = "last_name", nullable = false)
  @Convert(converter = EncryptedStringAttributeConverter.class)
  private String lastName;

  @Column(name = "middle_name")
  @Convert(converter = EncryptedStringAttributeConverter.class)
  private String middleName;

  @Column(name = "phone")
  @Convert(converter = EncryptedStringAttributeConverter.class)
  private String phone;

  @Column(name = "phone_hash", unique = true)
  private String phoneHash;

  @Column(name = "created_at", nullable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @PrePersist
  protected void onCreate() {
    syncDerivedFields();
    createdAt = LocalDateTime.now();
    updatedAt = LocalDateTime.now();
  }

  @PreUpdate
  protected void onUpdate() {
    syncDerivedFields();
    updatedAt = LocalDateTime.now();
  }

  private void syncDerivedFields() {
    phoneHash = AttributeHashingService.sha256(phone);
  }
}
