package secure_policy

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
)

// SessionPageID is strictly reserved for JTI short-term token blacklists
const SessionPageID = ultimate_db.PageID(6)

type SessionManager struct {
	db         *ultimate_db.DB
	signingKey *rsa.PrivateKey
}

func NewSessionManager(db *ultimate_db.DB, key *rsa.PrivateKey) *SessionManager {
	return &SessionManager{
		db:         db,
		signingKey: key,
	}
}

// GenerateJTI creates a cryptographically secure unique token ID for revocation tracking
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// IssueCookieToken generates a JWT bound to the hardware subject
func (sm *SessionManager) IssueCookieToken(subject []byte, ttl time.Duration) (string, string, error) {
	subjectID := string(subject)
	jti := generateJTI()
	now := time.Now()

	claims := jwt.MapClaims{
		"sub": subjectID,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(sm.signingKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, jti, nil
}

// ValidateCookieToken checks signature, expiration, and the dual-tier cache/DB blacklists
func (sm *SessionManager) ValidateCookieToken(tokenString string) (string, error) {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &sm.signingKey.PublicKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	subjectID := claims["sub"].(string)
	jti := claims["jti"].(string)

	hashedSub := hashSubject([]byte(subjectID))
	deviceKillKey := "blacklist:device:" + hashedSub
	sessionKillKey := "blacklist:jti:" + jti

	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	// --- 1. EVALUATE GLOBAL DEVICE KILL SWITCH (Cache-First) ---
	devData, err := ultimate_db.GlobalCacheStore.Read(txID, deviceKillKey)
	if err != nil {
		// Fall back to PolicyPageID (5) where global revocations live
		txn := sm.db.BeginTxn()
		devData, err = sm.db.Read(PolicyPageID, txn, []byte(deviceKillKey))
		sm.db.CommitTxn(txn)
		if err == nil && len(devData) > 0 {
			_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{deviceKillKey: devData}, 0)
		}
	}
	if len(devData) > 0 {
		return "", errors.New("device identity has been revoked")
	}

	// --- 2. EVALUATE SPECIFIC SESSION KILL SWITCH (Cache-First) ---
	sessData, err := ultimate_db.GlobalCacheStore.Read(txID, sessionKillKey)
	if err != nil {
		txn := sm.db.BeginTxn()
		sessData, err = sm.db.Read(SessionPageID, txn, []byte(sessionKillKey))
		sm.db.CommitTxn(txn)
		if err == nil && len(sessData) > 0 {
			_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{sessionKillKey: sessData}, 0)
		}
	}
	if len(sessData) > 0 {
		return "", errors.New("session has been revoked")
	}

	return subjectID, nil
}

// RevokeTokenString parses an unverified token to extract the JTI and revokes it.
func (sm *SessionManager) RevokeTokenString(tokenString string) error {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			return sm.RevokeSession(jti, 24*time.Hour)
		}
	}
	return errors.New("could not extract JTI from token")
}

// RevokeSession invalidates a specific JWT session token immediately across memory and disk
func (sm *SessionManager) RevokeSession(jti string, expiry time.Duration) error {
	compositeKey := "blacklist:jti:" + jti
	marker := []byte("revoked")

	// 1. Evict instantly from the fast cache layer to sever active sessions within microseconds
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: marker}, expiry); err != nil {
		return fmt.Errorf("session cache revocation abort: %w", err)
	}

	// 2. Persist to storage page blocks for durability
	txn := sm.db.BeginTxn()
	err := sm.db.Write(SessionPageID, txn, []byte(compositeKey), marker, expiry)
	sm.db.CommitTxn(txn)
	return err
}

// RevokeDevice permanently blacklists the hardware identity globally across page structures
func (sm *SessionManager) RevokeDevice(subject []byte) error {
	hashedSub := hashSubject(subject)
	compositeKey := "blacklist:device:" + hashedSub
	marker := []byte("revoked")

	// 1. Evict globally from memory
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: marker}, 0); err != nil {
		return fmt.Errorf("device cache revocation abort: %w", err)
	}

	// 2. Write to PolicyPageID (5) to align with secure_policy validation vectors
	txn := sm.db.BeginTxn()
	err := sm.db.Write(PolicyPageID, txn, []byte(compositeKey), marker, 0)
	sm.db.CommitTxn(txn)
	return err
}
