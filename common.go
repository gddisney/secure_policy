package secure_policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/0TrustCloud/secure_data_format"
)

// hashSubject standardizes a variable-length identity context string into a fixed SHA-256 hex format.
func hashSubject(subject []byte) string {
	h := sha256.Sum256(subject)
	return hex.EncodeToString(h[:])
}

// getNextNonce queries the active SDF storage layer to resolve and increment 
// the sequential tracking nonce for a specific resource address.
func getNextNonce(engine *secure_data_format.SecureDataEngine, profile string, targetAddress string) uint64 {
	worldStateKey := fmt.Sprintf("state:%s:%s", profile, targetAddress)
	txn := engine.Store.Begin()
	defer txn.Abort()

	data, err := engine.Store.Get(txn, []byte(worldStateKey))
	if err != nil || len(data) == 0 {
		return 0
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(data, &meta); err == nil {
		if n, ok := meta["nonce"].(float64); ok {
			return uint64(n) + 1
		}
	}
	return 0
}
