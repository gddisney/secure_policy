package secure_policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/0TrustCloud/ultimate_db"
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

// isRevoked leverages non-blocking snapshot reads across our lock-free memory cache layer
func (pe *PolicyEngine) isRevoked(txID uint64, txn uint64, subjectID string) bool {
	compositeKey := "blacklist:device:" + subjectID

	// 1. Check MVCC Lock-Free Fast Cache
	data, err := ultimate_db.GlobalCacheStore.Read(txID, compositeKey)
	if err == nil {
		return len(data) > 0
	}

	// 2. Fall back to slotted storage frame on cache miss
	data, err = pe.db.Read(PolicyPageID, txn, []byte(compositeKey))
	if err == nil && len(data) > 0 {
		// Repopulate cache frame to accelerate subsequent access assertions
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: data}, 0)
		return true
	}

	return false
}

// HasPermission executes an explicit permission lookup path optimized for real-time mesh routing loops
func (pe *PolicyEngine) HasPermission(subject []byte, permission string) bool {
	subjectID := hashSubject(subject)
	
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := pe.db.BeginTxn()
	defer pe.db.CommitTxn(txn)

	if pe.isRevoked(txID, txn, subjectID) {
		return false
	}

	compositeKey := fmt.Sprintf("perm:%s:%s", subjectID, permission)

	// Attempt reading directly from MVCC Lock-Free Cache first
	data, err := ultimate_db.GlobalCacheStore.Read(txID, compositeKey)
	if err == nil {
		return len(data) > 0
	}

	// Fallback to Slotted Page Durability Store on cache miss
	data, err = pe.db.Read(PolicyPageID, txn, []byte(compositeKey))
	if err == nil && len(data) > 0 {
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: data}, 0)
		return true
	}

	return false
}

// Evaluate runs a dual-stage PBAC/ABAC check with strict Deny-Override over unified transactional layers
func (pe *PolicyEngine) Evaluate(subject []byte, action, resource string, context map[string]string) bool {
	subjectID := hashSubject(subject)

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := pe.db.BeginTxn()
	defer pe.db.CommitTxn(txn) 

	if pe.isRevoked(txID, txn, subjectID) {
		return false
	}

	// --- STAGE 1: PBAC check (Fast Cache Resolution Path) ---
	permKey := fmt.Sprintf("perm:%s:%s", subjectID, action)
	if permData, err := ultimate_db.GlobalCacheStore.Read(txID, permKey); err == nil && len(permData) > 0 {
		return true
	}
	if permData, err := pe.db.Read(PolicyPageID, txn, []byte(permKey)); err == nil && len(permData) > 0 {
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{permKey: permData}, 0)
		return true
	}

	// --- STAGE 2: ABAC check (Fallback Chunk Hierarchy Path) ---
	potentialKeys := []string{
		fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource),
		fmt.Sprintf("policy:%s:%s:*", subjectID, action),
		fmt.Sprintf("policy:%s:*:*", subjectID),
	}

	isAllowed := false

	for _, k := range potentialKeys {
		var data []byte
		var err error

		// Leverage lock-free memory space for policy evaluation matrix
		data, err = ultimate_db.GlobalCacheStore.Read(txID, k)
		if err != nil {
			data, err = pe.db.Read(PolicyPageID, txn, []byte(k))
			if err != nil || len(data) == 0 {
				continue
			}
			_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{k: data}, 0)
		}

		if len(data) == 0 {
			continue 
		}

		var p Policy
		if err := json.Unmarshal(data, &p); err != nil {
			continue 
		}

		if pe.checkConditions(p.Conditions, context) {
			// SECURITY: Strict Deny-Override
			if p.Effect == "DENY" {
				return false
			}
			
			if p.Effect == "ALLOW" {
				isAllowed = true
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
	compositeKey := "blacklist:device:" + subjectID
	marker := []byte("revoked")

	// 1. Evict instantly from the high-speed cache ring to break active sessions within microseconds
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: marker}, 0); err != nil {
		return fmt.Errorf("cache eviction phase interrupted: %w", err)
	}

	// 2. Commit permanently to durable slotted page layouts
	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, []byte(compositeKey), marker, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) RestoreSubject(subject []byte) error {
	subjectID := hashSubject(subject)
	compositeKey := "blacklist:device:" + subjectID

	// Clear tombstone values straight through the cache layer
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: nil}, 0); err != nil {
		return fmt.Errorf("cache extraction failed: %w", err)
	}

	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, []byte(compositeKey), []byte{}, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) GrantPermission(subject []byte, permission string) error {
	subjectID := hashSubject(subject)
	compositeKey := fmt.Sprintf("perm:%s:%s", subjectID, permission)
	val := []byte("ok")

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: val}, 0); err != nil {
		return err
	}

	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, []byte(compositeKey), val, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) AddPolicy(subject []byte, action, resource, effect string, conditions map[string]string) error {
	subjectID := hashSubject(subject)
	compositeKey := fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource)
	
	policy := Policy{Effect: effect, Conditions: conditions}
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: data}, 0); err != nil {
		return err
	}

	txn := pe.db.BeginTxn()
	err = pe.db.Write(PolicyPageID, txn, []byte(compositeKey), data, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) RemovePolicy(subject []byte, action, resource string) error {
	subjectID := hashSubject(subject)
	compositeKey := fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource)
	
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	if err := ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{compositeKey: nil}, 0); err != nil {
		return err
	}

	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, []byte(compositeKey), []byte{}, 0) 
	pe.db.CommitTxn(txn)
	return err
}
