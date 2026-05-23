# `secure_policy`

`secure_policy` is a high-performance, hybrid Authorization Engine designed for decentralized Go microservices. It implements a two-tier security model combining **PBAC (Permission-Based Access Control)** for rapid decision-making and **ABAC (Attribute-Based Access Control)** for context-aware, granular policy enforcement.

It is built to integrate directly with [ultimate_db](https://www.google.com/search?q=https://github.com/gddisney/ultimate_db), ensuring that security policies are persisted, transactionally consistent, and easily replicated across a peer-to-peer mesh.

## Features

* **Hybrid Security Architecture**:
* **Fast-Path PBAC**: O(1) lookups for explicit, static permissions.
* **ABAC Fallback**: Logic-heavy, attribute-based evaluation for dynamic context (e.g., matching IPs, service names, or time-based conditions).


* **Default-Deny Posture**: If an error occurs or no policy is found, the engine defaults to `false` (Deny).
* **Deny-Override Logic**: Explicit `DENY` policies always supersede `ALLOW` policies, ensuring high-security constraints are respected.
* **Wildcard Support**: Built-in support for subject and action wildcards to simplify administration.
* **Transactional Integrity**: Leverages `ultimate_db` ACID transactions to ensure policy updates are atomic.

## Usage

### 1. Initialization

The engine requires a `*ultimate_db.DB` instance. It maps policies to `PolicyPageID` (5).

```go
import "github.com/gddisney/secure_policy"

// Initialize with your existing database
policyEngine := secure_policy.NewPolicyEngine(db)

```

### 2. PBAC: Granting Permissions

For high-frequency checks, grant explicit permissions that bypass complex attribute logic.

```go
// Allow a specific subject (Ed25519 PubKey) to 'ingest' logs
subject := []byte("...node-pubkey...")
err := policyEngine.GrantPermission(subject, "ingest")

```

### 3. ABAC: Evaluating Dynamic Policies

For more complex scenarios, add policies that require specific context (e.g., only allow access from a specific IP).

```go
// Add a policy: Subject X can perform 'read' on 'logs_db' only if IP matches
conditions := map[string]string{"ip": "10.0.0.5"}
policyEngine.AddPolicy(subject, "read", "logs_db", "ALLOW", conditions)

// Evaluate access at runtime
context := map[string]string{"ip": "10.0.0.5"}
if policyEngine.Evaluate(subject, "read", "logs_db", context) {
    // Access granted
}

```

## How It Works

### The Authorization Flow

When `Evaluate()` is called, the engine processes requests in a two-stage pipeline:

1. **Fast-Path (PBAC)**: Checks the `perm:` key prefix in `ultimate_db`. If an explicit permission exists, it returns `true` immediately.
2. **Fallback (ABAC)**: If no explicit permission is found, it queries the `policy:` key prefix. It searches for specific matches, then falls back to action wildcards (`*`) and subject wildcards.
3. **Conflict Resolution**: During evaluation, if any matching policy has an effect of `DENY`, the engine immediately returns `false`, overriding any existing `ALLOW` policies.

### Storage Layout

Policies are stored in `ultimate_db` using the following keys:

* `perm:<hex_subject>:<permission>`
* `policy:<hex_subject>:<action>:<resource>`

## Integration with Middleware

This engine is designed to be injected into your `Router` or `RPCManager`.

```go
// Example Middleware implementation
func AuthMiddleware(pe *secure_policy.PolicyEngine, action string) {
    // ... extract user identity and context ...
    if !pe.Evaluate(userKey, action, "resource_name", runtimeContext) {
        // Reject request
    }
}

```

## License

MIT License.
