package anytls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// PasswordModeRaw16 is the `password-mode` value that selects the Shanlian
// vendor first-packet credential: the password must be the bare 32 hex form, and
// the credential is `raw16 || (BE64(u*10+1) || BE64(u)) XOR raw16` where raw16 is
// the decoded key and u is the connection's Unix time in milliseconds (see
// deriveHexPasswordCredential). "raw16" names the first half of the credential:
// the raw 16 byte key instead of sha256(password).
const PasswordModeRaw16 = "raw16"

// hexPasswordPattern matches the vendor bare password form: 32 hex characters,
// i.e. the hexadecimal encoding of the 16 byte shared key.
var hexPasswordPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// normalizePasswordMode validates the explicit credential scheme selector. An
// empty value is the standard anytls path; only PasswordModeRaw16 turns on the
// vendor derivation. Unknown values fail closed instead of silently falling
// back, so a typo cannot masquerade as "standard anytls".
func normalizePasswordMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return "", nil
	case PasswordModeRaw16:
		return PasswordModeRaw16, nil
	default:
		return "", fmt.Errorf("anytls: unsupported password-mode %q (want %q)", mode, PasswordModeRaw16)
	}
}

// decodeHexPasswordKey returns the 16 byte shared key encoded by password when
// it is exactly 32 hex characters. ok is false for every other form (the "#sl"
// marker variant, ordinary anytls passwords, wrong lengths, invalid hex), which
// keep their existing decoding untouched.
//
// It only decodes the form; whether the derived credential is used is decided
// by ClientConfig.PasswordMode (see NewClient), never by the password shape alone.
func decodeHexPasswordKey(password string) (key []byte, ok bool) {
	if !hexPasswordPattern.MatchString(password) {
		return nil, false
	}
	decoded, err := hex.DecodeString(password)
	if err != nil || len(decoded) != hexPasswordKeySize {
		return nil, false
	}
	return decoded, true
}

// deriveHexPasswordCredential reproduces the vendor client's 32 byte first
// packet credential (applyAnyTLSHexPassword in the official fork):
//
//	cred = raw16 || (T16 XOR raw16)
//	T16  = BE64(u*10+1) || BE64(u)
//
// raw16 is the decoded 16 byte key and u is Unix time in milliseconds. It
// returns nil for a malformed key so callers fall back to passwordSha256
// instead of panicking.
func deriveHexPasswordCredential(raw []byte, u int64) []byte {
	if len(raw) != hexPasswordKeySize {
		return nil
	}
	millis := uint64(u)
	var token [hexPasswordKeySize]byte
	binary.BigEndian.PutUint64(token[0:8], millis*10+1)
	binary.BigEndian.PutUint64(token[8:16], millis)

	credential := make([]byte, hexPasswordCredentialSize)
	copy(credential, raw)
	for i := range token {
		credential[hexPasswordKeySize+i] = token[i] ^ raw[i]
	}
	return credential
}

// ShanlianPasswordMarker is the suffix the vendor client puts on a Shanlian
// node's password: the part before it is the raw 32-byte key in hex and is used
// directly as passwordSha256 instead of hashing the literal string.
const ShanlianPasswordMarker = "#sl"

// IsShanlianPassword reports whether password carries the Shanlian marker. The
// marker match is case-insensitive.
func IsShanlianPassword(password string) bool {
	return strings.HasSuffix(strings.ToLower(password), ShanlianPasswordMarker)
}

func decodeClientPassword(password string) ([]byte, error) {
	if IsShanlianPassword(password) {
		raw := password[:len(password)-len(ShanlianPasswordMarker)]
		if len(raw) != sha256.Size*2 {
			return nil, errors.New("anytls: Shanlian password must be 64 hexadecimal characters before #sl")
		}
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("anytls: invalid Shanlian hexadecimal password: %w", err)
		}
		return decoded, nil
	}
	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}
