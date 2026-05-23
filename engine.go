package secure_policy

import (
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

// 1. PBAC LAYER: Explicit Permission Check
// Fast O(1) lookup. Does the subject have this permission?
func (pe *PolicyEngine) HasPermission(subject []byte, permission string) bool {
	key := []byte(fmt.Sprintf("perm:%s:%s", hex.EncodeToString(subject), permission))
	
	txn := pe.db.BeginTxn()
	_, err := pe.db.Read(PolicyPageID, txn, key)
	pe.db.CommitTxn(txn)
	
	return err == nil
}

// 2. ABAC LAYER: Attribute Evaluation
// Slower, logic-heavy lookup for dynamic context.
func (pe *PolicyEngine) Evaluate(subject []byte, action, resource string, context map[string]string) bool {
	// --- STAGE 1: PBAC check (Fast Path) ---
	if pe.HasPermission(subject, action) {
		return true
	}

	// --- STAGE 2: ABAC check (Fallback Path) ---
	subjectHex := hex.EncodeToString(subject)
	
	// Check specific rule, action wildcard, and subject wildcard
	potentialKeys := []string{
		fmt.Sprintf("policy:%s:%s:%s", subjectHex, action, resource),
		fmt.Sprintf("policy:%s:%s:*", subjectHex, action),
		fmt.Sprintf("policy:%s:*:*", subjectHex),
	}

	txn := pe.db.BeginTxn()
	defer pe.db.CommitTxn(txn) // Ensure transaction handle is always released

	for _, k := range potentialKeys {
		data, err := pe.db.Read(PolicyPageID, txn, []byte(k))
		if err != nil {
			continue // Check next potential key
		}

		var p Policy
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}

		// Security Enhancement: Deny-Override
		// If ANY matching policy is DENY, reject immediately.
		if p.Effect == "DENY" {
			return false
		}

		// ABAC Condition Check
		if p.Effect == "ALLOW" && pe.checkConditions(p.Conditions, context) {
			return true
		}
	}

	return false // Default DENY
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

func (pe *PolicyEngine) GrantPermission(subject []byte, permission string) error {
	key := []byte(fmt.Sprintf("perm:%s:%s", hex.EncodeToString(subject), permission))
	
	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, key, []byte("ok"), 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) AddPolicy(subject []byte, action, resource, effect string, conditions map[string]string) error {
	key := []byte(fmt.Sprintf("policy:%s:%s:%s", hex.EncodeToString(subject), action, resource))
	policy := Policy{Effect: effect, Conditions: conditions}
	data, _ := json.Marshal(policy)

	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, key, data, 0)
	pe.db.CommitTxn(txn)
	return err
}

func (pe *PolicyEngine) RemovePolicy(subject []byte, action, resource string) error {
	key := []byte(fmt.Sprintf("policy:%s:%s:%s", hex.EncodeToString(subject), action, resource))
	
	txn := pe.db.BeginTxn()
	err := pe.db.Write(PolicyPageID, txn, key, nil, 0) // Overwrite with empty to "delete"
	pe.db.CommitTxn(txn)
	return err
}


// PolicyDisplay is used to send formatted policy data to the UI templates
type PolicyDisplay struct {
	Resource string
	Action   string
	Effect   string
}

// GetPolicies retrieves a list of policies bound to a subject.
// Note: In a production KV store, this requires a prefix scanner over "policy:subjectHex:*"
func (pe *PolicyEngine) GetPolicies(subject []byte) []PolicyDisplay {
	// Stub returning a placeholder until DB iteration is implemented
	return []PolicyDisplay{
		{Resource: "admin_dashboard", Action: "access", Effect: "ALLOW"},
		{Resource: "audit_logs", Action: "read", Effect: "ALLOW"},
	}
}
