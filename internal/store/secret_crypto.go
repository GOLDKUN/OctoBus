package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	encryptedSecretPrefix = "octobus-secret-v1:"
	secretKeyEnv          = "OCTOBUS_SECRET_ENCRYPTION_KEY"
	secretKeyBytes        = 32
)

func loadSecretKey(dbPath string) ([]byte, error) {
	if encoded := os.Getenv(secretKeyEnv); encoded != "" {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != secretKeyBytes {
			return nil, fmt.Errorf("%s must be base64-encoded %d-byte key", secretKeyEnv, secretKeyBytes)
		}
		return key, nil
	}
	if dbPath == ":memory:" {
		return randomSecretKey()
	}

	keyPath := dbPath + ".secret-key"
	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) != secretKeyBytes {
			return nil, fmt.Errorf("secret key file %q has invalid length", keyPath)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err = randomSecretKey()
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, writeErr := file.Write(key); writeErr != nil {
			_ = file.Close()
			_ = os.Remove(keyPath)
			return nil, writeErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	key, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(key) != secretKeyBytes {
		return nil, fmt.Errorf("secret key file %q has invalid length", keyPath)
	}
	return key, nil
}

func randomSecretKey() ([]byte, error) {
	key := make([]byte, secretKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptSecret(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return encryptedSecretPrefix + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(key []byte, encoded string) ([]byte, error) {
	if len(encoded) < len(encryptedSecretPrefix) || encoded[:len(encryptedSecretPrefix)] != encryptedSecretPrefix {
		return []byte(encoded), nil
	}
	payload, err := base64.RawStdEncoding.DecodeString(encoded[len(encryptedSecretPrefix):])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted instance secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize() {
		return nil, errors.New("encrypted instance secret is truncated")
	}
	return gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], nil)
}

func (s *Store) encryptLegacySecrets(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, secret_json FROM instances WHERE secret_json <> '' AND substr(secret_json, 1, ?) <> ?`, len(encryptedSecretPrefix), encryptedSecretPrefix)
	if err != nil {
		return err
	}
	type legacySecret struct {
		id   string
		data string
	}
	var legacy []legacySecret
	for rows.Next() {
		var item legacySecret
		if err := rows.Scan(&item.id, &item.data); err != nil {
			_ = rows.Close()
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(legacy) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range legacy {
		encrypted, err := encryptSecret(s.secretKey, []byte(item.data))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE instances SET secret_json = ? WHERE id = ?`, encrypted, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
