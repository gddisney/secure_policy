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
	// FIX: Store the RAW username in the JWT, do not hash it here
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

// ValidateCookieToken checks signature, expiration, and the DB blacklist
func (sm *SessionManager) ValidateCookieToken(tokenString string) (string, error) {
	// FIX: Transparently strip the legacy prefix before parsing the JWT
	import "strings" // Ensure this is in your imports at the top of session.go
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

	// This is now the RAW username
	subjectID := claims["sub"].(string)
	jti := claims["jti"].(string)

	txn := sm.db.BeginTxn()
	defer sm.db.CommitTxn(txn)

	// FIX: Hash the raw username specifically for the database lookup
	hashedSub := hashSubject([]byte(subjectID))

	// 1. Check Global Device Kill Switch
	deviceKillKey := []byte("blacklist:device:" + hashedSub)
	if data, _ := sm.db.Read(SessionPageID, txn, deviceKillKey); len(data) > 0 {
		return "", errors.New("device identity has been revoked")
	}

	// 2. Check Specific Session Kill Switch
	sessionKillKey := []byte("blacklist:jti:" + jti)
	if data, _ := sm.db.Read(SessionPageID, txn, sessionKillKey); len(data) > 0 {
		return "", errors.New("session has been revoked")
	}

	// Returns raw username so pe.Evaluate can hash it correctly
	return subjectID, nil 
}

// RevokeTokenString parses an unverified token to extract the JTI and revokes it.
func (sm *SessionManager) RevokeTokenString(tokenString string) error {
	// FIX: Strip the prefix here too
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
