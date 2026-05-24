package secure_policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gddisney/ultimate_db"
)

const PolicyPageID = ultimate_db.PageID(5)

type Policy struct {
	Effect     string            `json:"effect"`     // "ALLOW" or "DENY"
	Conditions map[string]string `json:"conditions"` // Attribute constraints
}

type PolicyEngine struct {
	db *ultimate_db.DB
}

func NewPolicyEngine(db *ultimate_db.DB) *PolicyEngine {
	return &PolicyEngine{db: db}
}

// hashSubject standardizes the variable-length TPM/Passkey into a fixed-length string
func hashSubject(subject []byte) string {
	h := sha256.Sum256(subject)
	return hex.EncodeToString(h[:])
}

// isRevoked checks the global kill switch for a cryptographic identity
func (pe *PolicyEngine) isRevoked(txn interface{}, subjectID string) bool {
	key := []byte("blacklist:device:" + subjectID)
	data, err := pe.db.Read(PolicyPageID, txn, key)
	// If the key exists and has data, the device is blacklisted
	return err == nil && len(data) > 0
}

// 1. PBAC LAYER: Explicit Permission Check
func (pe *PolicyEngine) HasPermission(subject []byte, permission string) bool {
	subjectID := hashSubject(subject)
	
	txn := pe.db.BeginTxn()
	defer pe.db.CommitTxn(txn)

	// SECURITY: Hard fail if the identity is revoked
	if pe.isRevoked(txn, subjectID) {
		return false
	}

	key := []byte(fmt.Sprintf("perm:%s:%s", subjectID, permission))
	data, err := pe.db.Read(PolicyPageID, txn, key)
	
	// Ensure the key exists and isn't a tombstone
	return err == nil && len(data) > 0
}

// 2. ABAC LAYER: Attribute Evaluation
func (pe *PolicyEngine) Evaluate(subject []byte, action, resource string, context map[string]string) bool {
	subjectID := hashSubject(subject)

	txn := pe.db.BeginTxn()
	defer pe.db.CommitTxn(txn) 

	// SECURITY: Hard fail if the identity is revoked
	if pe.isRevoked(txn, subjectID) {
		return false
	}

	// --- STAGE 1: PBAC check (Fast Path) ---
	permKey := []byte(fmt.Sprintf("perm:%s:%s", subjectID, action))
	if permData, err := pe.db.Read(PolicyPageID, txn, permKey); err == nil && len(permData) > 0 {
		return true
	}

	// --- STAGE 2: ABAC check (Fallback Path) ---
	potentialKeys := []string{
		fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource),
		fmt.Sprintf("policy:%s:%s:*", subjectID, action),
		fmt.Sprintf("policy:%s:*:*", subjectID),
	}

	isAllowed := false

	for _, k := range potentialKeys {
		data, err := pe.db.Read(PolicyPageID, txn, []byte(k))
		
		// Ignore not found errors or empty tombstone data
		if err != nil || len(data) == 0 {
			continue 
		}

		var p Policy
		if err := json.Unmarshal(data, &p); err != nil {
			continue // Skip malformed policies
		}

		if pe.checkConditions(p.Conditions, context) {
			// SECURITY: Strict Deny-Override
			// If ANY matching policy evaluates to DENY, reject immediately.
			if p.Effect == "DENY" {
				return false
			}
			
			if p.Effect == "ALLOW" {
				isAllowed = true
				// Do not return true immediately; continue loop to ensure no broader DENY exists
			}
		}
	}

	return isAllowed 
}

func (pe *PolicyEngine) checkConditions(required map[string]string, actual map[string]string) bool {
	if len(required) == 0 { return true }
	
	for k, v := range required {
		if val, ok := actual[k]; !ok || val != v {
			return false
		}
	}
	return true
}

// --- Management API ---

func (pe *PolicyEngine) RevokeSubject(subject []byte) error {
	subjectID := hashSubject(subject)
	key := []byte("blacklist:device:" + subjectID)
	
	txn := pe.db.BeginTxn()
	// Write a permanent blacklist marker (TTL 0)
	err := pe.db.Write(PolicyPageID, txn, key, []byte("revoked"), 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) RestoreSubject(subject []byte) error {
	subjectID := hashSubject(subject)
	key := []byte("blacklist:device:" + subjectID)
	
	txn := pe.db.BeginTxn()
	// Write tombstone to remove blacklist
	err := pe.db.Write(PolicyPageID, txn, key, []byte{}, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) GrantPermission(subject []byte, permission string) error {
	subjectID := hashSubject(subject)
	key := []byte(fmt.Sprintf("perm:%s:%s", subjectID, permission))
	
	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, key, []byte("ok"), 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) AddPolicy(subject []byte, action, resource, effect string, conditions map[string]string) error {
	subjectID := hashSubject(subject)
	key := []byte(fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource))
	
	policy := Policy{Effect: effect, Conditions: conditions}
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	txn := pe.db.BeginTxn()
	err = pe.db.Write(PolicyPageID, txn, key, data, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) RemovePolicy(subject []byte, action, resource string) error {
	subjectID := hashSubject(subject)
	key := []byte(fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource))
	
	txn := pe.db.BeginTxn()
	// Overwrite with empty byte slice to act as a tombstone
	err := pe.db.Write(PolicyPageID, txn, key, []byte{}, 0) 
	pe.db.CommitTxn(txn)
	return err
}
