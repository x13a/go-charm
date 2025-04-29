package charm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	wantedCipherText = "608f6530c6cdbf6bd43a1ff4e9"
	wantedTag        = "7747c9709e104b2168517a5bafa32b89"
	wantedHash       = "4bf3de4fa09195a31d7d40e599156dabb81fc49be37b876e23541ac2343fa668"
)

var (
	testKey = func() []byte {
		return fillBytes(KeyLength, 1)
	}
	testNonce = func() []byte {
		return fillBytes(NonceLength, 2)
	}
	testMsg = func() []byte {
		return []byte("Hello, World!")
	}
)

func fillBytes(n int, val byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = val
	}
	return b
}

func clone(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func Test_EncryptDecrypt(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	msg := testMsg()
	message := clone(msg)
	charm, err := NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (enc) failed: %v", err)
	}
	tag := charm.Encrypt(message)
	if len(tag) != TagLength {
		t.Fatalf("Encrypt returned tag with wrong length: expected %d, got %d", TagLength, len(tag))
	}
	if s := hex.EncodeToString(message); wantedCipherText != s {
		t.Fatalf("Ciphertext mismatch: expected %s, got %s", wantedCipherText, s)
	}
	if s := hex.EncodeToString(tag); wantedTag != s {
		t.Fatalf("Tag mismatch: expected %s, got %s", wantedTag, s)
	}
	charm, err = NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (dec) failed: %v", err)
	}
	if err = charm.Decrypt(message, tag); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(message, msg) {
		t.Fatalf("Decrypted message mismatch: expected '%s', got '%s'", msg, message)
	}
}

func Test_Hash(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	msg := testMsg()
	charm, err := NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (1) failed: %v", err)
	}
	hash1 := charm.Hash(msg)
	if len(hash1) != HashLength {
		t.Fatalf("Hash returned hash with wrong length: expected %d, got %d", HashLength, len(hash1))
	}
	if s := hex.EncodeToString(hash1); wantedHash != s {
		t.Fatalf("Hash mismatch: expected %s, got %s", wantedHash, s)
	}
	charm, err = NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (2) failed: %v", err)
	}
	hash2 := charm.Hash(msg)
	if !bytes.Equal(hash1, hash2) {
		t.Fatalf("Hashes do not match:\nHash1: %x\nHash2: %x", hash1, hash2)
	}
}

func Test_DecryptFailWrongTag(t *testing.T) {
	key := testKey()
	nonce := testNonce()
	msg := testMsg()
	message := clone(msg)
	charm, err := NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (enc) failed: %v", err)
	}
	charm.Encrypt(message)
	wrongTag := fillBytes(TagLength, 0)
	charm, err = NewCharm(key, nonce)
	if err != nil {
		t.Fatalf("NewCharm (dec) failed: %v", err)
	}
	err = charm.Decrypt(message, wrongTag)
	if err == nil {
		t.Fatalf("Expected verification error, but Decrypt succeeded")
	}
	if !errors.Is(err, ErrTagVerifyFail) {
		t.Fatalf("Expected '%v' error, got: %v", ErrTagVerifyFail, err)
	}
}
