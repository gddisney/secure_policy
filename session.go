package secure_policy

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gddisney/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
)

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
	rand.Read(b)
	return hex.EncodeToString(b)
}

// IssueCookieToken generates a JWT bound to the hardware subject
func (sm *SessionManager) IssueCookieToken(subject []byte, ttl time.Duration) (string, string, error) {
	subjectID := hashSubject(subject) // From your hardened PolicyEngine
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

// ValidateCookieToken checks signature, expiration, and the DB blacklist
func (sm *SessionManager) ValidateCookieToken(tokenString string) (string, error) {
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

	// --- BLACKLIST CHECKS (O(1) Fast Lookups) ---
	txn := sm.db.BeginTxn()
	defer sm.db.CommitTxn(txn)

	// 1. Check Global Device Kill Switch (Is the TPM bricked/stolen?)
	deviceKillKey := []byte("blacklist:device:" + subjectID)
	if data, _ := sm.db.Read(SessionPageID, txn, deviceKillKey); len(data) > 0 {
		return "", errors.New("device identity has been revoked")
	}

	// 2. Check Specific Session Kill Switch (Did the user click 'log out'?)
	sessionKillKey := []byte("blacklist:jti:" + jti)
	if data, _ := sm.db.Read(SessionPageID, txn, sessionKillKey); len(data) > 0 {
		return "", errors.New("session has been revoked")
	}

	return subjectID, nil
}

// RevokeSession invalidates a specific JWT immediately
func (sm *SessionManager) RevokeSession(jti string, expiry time.Duration) error {
	txn := sm.db.BeginTxn()
	// The blacklist entry only needs to live until the JWT naturally expires
	err := sm.db.Write(SessionPageID, txn, []byte("blacklist:jti:"+jti), []byte("revoked"), expiry)
	sm.db.CommitTxn(txn)
	return err
}

// RevokeDevice permanently blacklists the hardware identity across all active sessions
func (sm *SessionManager) RevokeDevice(subject []byte) error {
	subjectID := hashSubject(subject)
	txn := sm.db.BeginTxn()
	// Write a permanent blacklist marker (0 TTL)
	err := sm.db.Write(SessionPageID, txn, []byte("blacklist:device:"+subjectID), []byte("revoked"), 0)
	sm.db.CommitTxn(txn)
	return err
}
// Add this to session.go

// RevokeTokenString parses an unverified token to extract the JTI and revokes it.
// This is safe because we only use it to add to a blacklist, not to grant access.
func (sm *SessionManager) RevokeTokenString(tokenString string) error {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			// Blacklist for 24 hours (or match your max token TTL)
			return sm.RevokeSession(jti, 24*time.Hour)
		}
	}
	return errors.New("could not extract JTI from token")
}
