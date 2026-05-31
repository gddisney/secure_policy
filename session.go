package secure_policy

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/golang-jwt/jwt/v5"
)

type SessionManager struct {
	sdfEngine *secure_data_format.SecureDataEngine
	publicKey *rsa.PublicKey
}

func NewSessionManager(sdf *secure_data_format.SecureDataEngine, pubKey *rsa.PublicKey) *SessionManager {
	return &SessionManager{
		sdfEngine: sdf,
		publicKey: pubKey,
	}
}

// =============================================================================
// Token Generation & Synthesis Path
// =============================================================================

func (sm *SessionManager) IssueCookieToken(subject []byte, ttl time.Duration) (string, string, error) {
	subjectID := string(subject)
	targetAddress := "session:user:" + hashSubject(subject)
	
	script := fmt.Sprintf(`session:identity(user("%s"))`, subjectID)
	nonce := getNextNonce(sm.sdfEngine, "grant", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-manager-core",
		Nonce:         nonce,
		Method:        "ISSUE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"sub": subjectID},
	}

	tokenStr, err := sm.sdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return "", "", fmt.Errorf("failed synthesizing token state: %w", err)
	}

	p := new(jwt.Parser)
	parsedToken, _, err := p.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", "", fmt.Errorf("failed reading compiled transaction properties: %w", err)
	}

	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	jti, _ := claims["jti"].(string)

	return tokenStr, jti, nil
}

// =============================================================================
// Validation & Verification Infrastructure
// =============================================================================

func (sm *SessionManager) ValidateCookieToken(tokenString string) (string, error) {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	if sm.publicKey == nil {
		return "", errors.New("cryptographic context error: public verification key unassigned")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sm.publicKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	stateUpdates, ok := claims["state_updates"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing structured payload context block")
	}

	subjectID, _ := stateUpdates["sub"].(string)
	jti, _ := claims["jti"].(string)

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := sm.sdfEngine.Store.Begin()
	defer txn.Commit()

	hashedSub := hashSubject([]byte(subjectID))
	if sm.isDeviceRevoked(txID, txn, hashedSub) {
		return "", errors.New("device identity has been revoked")
	}

	if sm.isSessionRevoked(txID, txn, jti) {
		return "", errors.New("session has been revoked")
	}

	return subjectID, nil
}

func (sm *SessionManager) isDeviceRevoked(txID uint64, txn ultimate_db.TxnHandle, hashedSub string) bool {
	targetAddress := "blacklist:device:" + hashedSub
	worldStateKey := "state:pop:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = sm.sdfEngine.Store.Get(txn, []byte(worldStateKey))
		if err != nil || len(stateData) == 0 {
			return false
		}
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(stateData, &meta); err != nil {
		return false
	}

	nonceVal, ok := meta["nonce"].(float64)
	if !ok {
		return false
	}

	ledgerKey := fmt.Sprintf("transaction_ledger:pop:%s:%d", targetAddress, uint64(nonceVal))
	var ledgerData []byte
	if ledgerData, err = ultimate_db.GlobalCacheStore.Read(txID, ledgerKey); err != nil {
		ledgerData, err = sm.sdfEngine.Store.Get(txn, []byte(ledgerKey))
		if err != nil || len(ledgerData) == 0 {
			return false
		}
	}

	var ledger map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		return false
	}

	return ledger["method"] == "REVOKE"
}

func (sm *SessionManager) isSessionRevoked(txID uint64, txn ultimate_db.TxnHandle, jti string) bool {
	targetAddress := "blacklist:jti:" + jti
	worldStateKey := "state:grant:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = sm.sdfEngine.Store.Get(txn, []byte(worldStateKey))
		if err != nil || len(stateData) == 0 {
			return false
		}
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(stateData, &meta); err != nil {
		return false
	}

	nonceVal, ok := meta["nonce"].(float64)
	if !ok {
		return false
	}

	ledgerKey := fmt.Sprintf("transaction_ledger:grant:%s:%d", targetAddress, uint64(nonceVal))
	var ledgerData []byte
	if ledgerData, err = ultimate_db.GlobalCacheStore.Read(txID, ledgerKey); err != nil {
		ledgerData, err = sm.sdfEngine.Store.Get(txn, []byte(ledgerKey))
		if err != nil || len(ledgerData) == 0 {
			return false
		}
	}

	var ledger map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		return false
	}

	return ledger["method"] == "REVOKE"
}

// =============================================================================
// Session Management / Revocation Mutation Interface
// =============================================================================

func (sm *SessionManager) RevokeTokenString(tokenString string) error {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	p := new(jwt.Parser)
	token, _, err := p.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			return sm.RevokeSession(jti, 24*time.Hour)
		}
	}
	return errors.New("could not extract JTI from token payload")
}

func (sm *SessionManager) RevokeSession(jti string, expiry time.Duration) error {
	targetAddress := "blacklist:jti:" + jti
	script := `blacklist:session(status("revoked"))`
	nonce := getNextNonce(sm.sdfEngine, "grant", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-admin-service",
		Nonce:         nonce,
		Method:        "REVOKE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"status": "revoked"},
	}

	_, err := sm.sdfEngine.CompileSecureData(script, tx)
	return err
}

func (sm *SessionManager) RevokeDevice(subject []byte) error {
	hashedSub := hashSubject(subject)
	targetAddress := "blacklist:device:" + hashedSub
	
	script := `blacklist:device(status("revoked"))`
	nonce := getNextNonce(sm.sdfEngine, "pop", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-admin-service",
		Nonce:         nonce,
		Method:        "REVOKE",
		Profile:       secure_data_format.ProfileProofOfPoss,
		Args:          map[string]interface{}{"status": "revoked"},
	}

	_, err := sm.sdfEngine.CompileSecureData(script, tx)
	return err
}
