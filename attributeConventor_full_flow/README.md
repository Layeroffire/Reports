# Full Attribute Converter Flow

This folder captures the whole process, not just phone encryption.

Flow:
1. `CryptoProperties` provides `app.crypto.enabled` and `app.crypto.secret`.
2. `AttributeEncryptionService` encrypts and decrypts string values.
3. `EncryptedStringAttributeConverter` plugs the service into JPA.
4. Entities mark sensitive fields with `@Convert`.
5. If a field must still support lookup or uniqueness, store a separate stable hash.
6. Add migration SQL for new derived columns and backfill existing rows.
7. Move auth and lookup flows to the hash-based access path, with temporary fallback for legacy rows.

Files:
- `CryptoProperties.java`
- `AttributeEncryptionService.java`
- `EncryptedStringAttributeConverter.java`
- `AddressEntity.java`
- `EventEntity.java`
- `AttributeHashingService.java`
- `PersonEntity.java`
- `ValidatePhoneUseCase.java`
- `AuthFlow.java`
- `v1.0.003__backfill-person-phone-hash.sql`
