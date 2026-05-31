package secure_policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/secure_data_format"
)

type Policy struct {
	Effect     string            `json:"effect"`     // "ALLOW" or "DENY"
	Conditions map[string]string `json:"conditions"` // Advanced attribute matching constraints
}

type PolicyEngine struct {
	sdfEngine *securedataformat.SecureDataEngine
}

func NewPolicyEngine(sdf *securedataformat.SecureDataEngine) *PolicyEngine {
	return &PolicyEngine{sdfEngine: sdf}
}

// isRevoked checks the hardware posture registry via cache-first ledger receipts
func (pe *PolicyEngine) isRevoked(txID uint64, txn ultimate_db.TxnHandle, subjectID string) bool {
	targetAddress := "blacklist:device:" + subjectID
	worldStateKey := "state:pop:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = pe.sdfEngine.Store.Get(txn, []byte(worldStateKey))
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
		ledgerData, err = pe.sdfEngine.Store.Get(txn, []byte(ledgerKey))
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

// HasPermission executes real-time permission validations across cached ledger tracking contexts
func (pe *PolicyEngine) HasPermission(subject []byte, permission string) bool {
	subjectID := hashSubject(subject)
	
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := pe.sdfEngine.Store.Begin()
	defer txn.Commit()

	if pe.isRevoked(txID, txn, subjectID) {
		return false
	}

	targetAddress := fmt.Sprintf("perm:%s:%s", subjectID, permission)
	worldStateKey := "state:grant:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = pe.sdfEngine.Store.Get(txn, []byte(worldStateKey))
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
		ledgerData, err = pe.sdfEngine.Store.Get(txn, []byte(ledgerKey))
		if err != nil || len(ledgerData) == 0 {
			return false
		}
	}

	var ledger map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		return false
	}

	return ledger["method"] == "GRANT"
}

// Evaluate runs hierarchical PBAC/ABAC scans with strict Deny-Override over SDF data layouts
func (pe *PolicyEngine) Evaluate(subject []byte, action, resource string, context map[string]string) bool {
	subjectID := hashSubject(subject)

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := pe.sdfEngine.Store.Begin()
	defer txn.Commit()

	if pe.isRevoked(txID, txn, subjectID) {
		return false
	}

	if pe.HasPermission(subject, action) {
		return true
	}

	potentialAddresses := []string{
		fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource),
		fmt.Sprintf("policy:%s:%s:*", subjectID, action),
		fmt.Sprintf("policy:%s:*:*", subjectID),
	}

	isAllowed := false

	for _, addr := range potentialAddresses {
		worldStateKey := "state:grant:" + addr
		var stateData []byte
		var err error

		if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
			stateData, err = pe.sdfEngine.Store.Get(txn, []byte(worldStateKey))
			if err != nil || len(stateData) == 0 {
				continue
			}
		}

		var meta map[string]interface{}
		if err := json.Unmarshal(stateData, &meta); err != nil {
			continue
		}

		nonceVal, _ := meta["nonce"].(float64)
		ledgerKey := fmt.Sprintf("transaction_ledger:grant:%s:%d", addr, uint64(nonceVal))
		
		var ledgerData []byte
		if ledgerData, err = ultimate_db.GlobalCacheStore.Read(txID, ledgerKey); err != nil {
			ledgerData, err = pe.sdfEngine.Store.Get(txn, []byte(ledgerKey))
			if err != nil || len(ledgerData) == 0 {
				continue
			}
		}

		var ledger map[string]interface{}
		if err := json.Unmarshal(ledgerData, &ledger); err != nil {
			continue
		}

		stateUpdates, ok := ledger["state_updates"].(map[string]interface{})
		if !ok {
			continue
		}

		effect, _ := stateUpdates["effect"].(string)
		rawConditions, ok := stateUpdates["conditions"].(map[string]interface{})
		if !ok {
			continue
		}

		conditions := make(map[string]string)
		for k, v := range rawConditions {
			if strVal, ok := v.(string); ok {
				conditions[k] = strVal
			}
		}

		if pe.checkConditions(conditions, context) {
			if effect == "DENY" {
				return false
			}
			if effect == "ALLOW" {
				isAllowed = true
			}
		}
	}

	return isAllowed
}

func (pe *PolicyEngine) checkConditions(required map[string]string, actual map[string]string) bool {
	if len(required) == 0 { return true }
	if actual == nil { return false }
	
	for k, pattern := range required {
		val, exists := actual[k]
		if !exists {
			return false
		}

		if strings.HasPrefix(pattern, "prefix:") {
			pfx := strings.TrimPrefix(pattern, "prefix:")
			if !strings.HasPrefix(val, pfx) {
				return false
			}
			continue
		}

		if strings.HasPrefix(pattern, "suffix:") {
			sfx := strings.TrimPrefix(pattern, "suffix:")
			if !strings.HasSuffix(val, sfx) {
				return false
			}
			continue
		}

		if val != pattern {
			return false
		}
	}
	return true
}

// =============================================================================
// Management Mutation Layer
// =============================================================================

func (pe *PolicyEngine) RevokeSubject(subject []byte) error {
	subjectID := hashSubject(subject)
	targetAddress := "blacklist:device:" + subjectID
	
	script := `blacklist:device(status("revoked"))`
	nonce := getNextNonce(pe.sdfEngine, "pop", targetAddress)

	tx := securedataformat.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "policy-admin-service",
		Nonce:         nonce,
		Method:        "REVOKE",
		Profile:       securedataformat.ProfileProofOfPoss,
		Args:          map[string]interface{}{"status": "revoked"},
	}

	_, err := pe.sdfEngine.CompileSecureData(script, tx)
	return err
}

func (pe *PolicyEngine) RestoreSubject(subject []byte) error {
	subjectID := hashSubject(subject)
	targetAddress := "blacklist:device:" + subjectID
	
	script := `blacklist:device(status("active"))`
	nonce := getNextNonce(pe.sdfEngine, "pop", targetAddress)

	tx := securedataformat.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "policy-admin-service",
		Nonce:         nonce,
		Method:        "RESTORE",
		Profile:       securedataformat.ProfileProofOfPoss,
		Args:          map[string]interface{}{"status": "active"},
	}

	_, err := pe.sdfEngine.CompileSecureData(script, tx)
	return err
}

func (pe *PolicyEngine) GrantPermission(subject []byte, permission string) error {
	subjectID := hashSubject(subject)
	targetAddress := fmt.Sprintf("perm:%s:%s", subjectID, permission)
	
	script := `perm:assignment(status("active"))`
	nonce := getNextNonce(pe.sdfEngine, "grant", targetAddress)

	tx := securedataformat.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "policy-admin-service",
		Nonce:         nonce,
		Method:        "GRANT",
		Profile:       securedataformat.ProfileGrant,
		Args:          map[string]interface{}{"status": "granted"},
	}

	_, err := pe.sdfEngine.CompileSecureData(script, tx)
	return err
}

func (pe *PolicyEngine) AddPolicy(subject []byte, action, resource, effect string, conditions map[string]string) error {
	subjectID := hashSubject(subject)
	targetAddress := fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource)
	
	script := fmt.Sprintf(`policy:statement(effect("%s"))`, effect)
	nonce := getNextNonce(pe.sdfEngine, "grant", targetAddress)

	tx := securedataformat.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "policy-admin-service",
		Nonce:         nonce,
		Method:        "ADD",
		Profile:       securedataformat.ProfileGrant,
		Args: map[string]interface{}{
			"effect":     effect,
			"conditions": conditions,
		},
	}

	_, err := pe.sdfEngine.CompileSecureData(script, tx)
	return err
}

func (pe *PolicyEngine) RemovePolicy(subject []byte, action, resource string) error {
	subjectID := hashSubject(subject)
	targetAddress := fmt.Sprintf("policy:%s:%s:%s", subjectID, action, resource)
	
	script := `policy:statement(status("deleted"))`
	nonce := getNextNonce(pe.sdfEngine, "grant", targetAddress)

	tx := securedataformat.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "policy-admin-service",
		Nonce:         nonce,
		Method:        "REMOVE",
		Profile:       securedataformat.ProfileGrant,
		Args:          map[string]interface{}{"effect": "DENY"},
	}

	_, err := pe.sdfEngine.CompileSecureData(script, tx)
	return err
}
