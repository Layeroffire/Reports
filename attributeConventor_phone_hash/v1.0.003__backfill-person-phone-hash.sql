ALTER TABLE person
    ADD COLUMN IF NOT EXISTS phone_hash varchar(64);

UPDATE person
SET phone_hash = encode(digest(phone, 'sha256'), 'hex')
WHERE phone IS NOT NULL
  AND btrim(phone) <> ''
  AND (phone_hash IS NULL OR btrim(phone_hash) = '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_person_phone_hash
    ON person (phone_hash)
    WHERE phone_hash IS NOT NULL;
