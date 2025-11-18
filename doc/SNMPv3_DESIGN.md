# SNMPv3 Implementation Design

## Overview

SNMPv3 adds **User-based Security Model (USM)** with authentication and privacy capabilities.
This implementation targets **authNoPriv** security level (authentication without encryption).

---

## Message Structure Comparison

### SNMPv1/v2c (Current)
```
SEQUENCE {
  version INTEGER (0 or 1)
  community OCTET STRING
  PDU (GetRequest/Response/etc)
}
```

### SNMPv3 (New)
```
SEQUENCE {
  msgVersion INTEGER (3)
  msgGlobalData HeaderData SEQUENCE {
    msgID INTEGER (0..2147483647)
    msgMaxSize INTEGER (484..2147483647)
    msgFlags OCTET STRING (1 byte)
      bit 0: authentication (1=yes, 0=no)
      bit 1: privacy/encryption (1=yes, 0=no)
      bit 2: reportable (1=yes, 0=no)
    msgSecurityModel INTEGER (3 for USM)
  }
  msgSecurityParameters OCTET STRING {
    SEQUENCE {  -- USM parameters (when decoded)
      msgAuthoritativeEngineID OCTET STRING (5-32 bytes)
      msgAuthoritativeEngineBoots INTEGER (0..2147483647)
      msgAuthoritativeEngineTime INTEGER (0..2147483647)
      msgUserName OCTET STRING (0-32 bytes)
      msgAuthenticationParameters OCTET STRING (12 bytes for HMAC)
      msgPrivacyParameters OCTET STRING (empty for authNoPriv)
    }
  }
  msgData ScopedPduData CHOICE {
    plaintext ScopedPDU SEQUENCE {
      contextEngineID OCTET STRING
      contextName OCTET STRING (default: "")
      data PDU (GetRequest/Response/etc)
    }
    encryptedPDU OCTET STRING  -- Not used in authNoPriv
  }
}
```

---

## Security Levels

| Level | Auth | Priv | msgFlags | Implementation Status |
|-------|------|------|----------|----------------------|
| noAuthNoPriv | ❌ | ❌ | 0x00 | Future (low priority) |
| authNoPriv | ✅ | ❌ | 0x01 | **Target** |
| authPriv | ✅ | ✅ | 0x03 | Future |

---

## USM Authentication Protocol

### Supported Algorithms

| Protocol | HMAC | Output Size | Java Class |
|----------|------|-------------|------------|
| MD5 | HMAC-MD5 | 16 bytes (use first 12) | HmacMD5 |
| SHA | HMAC-SHA-1 | 20 bytes (use first 12) | HmacSHA1 |

For authNoPriv: **msgAuthenticationParameters = first 12 bytes of HMAC**

---

## Key Localization Algorithm

SNMPv3 derives authentication keys from passwords using the engine ID.

### Password → Localized Key

```
1. Password-to-Key (Ku generation):

   Repeat password to fill 1 MB buffer:
   buf = password repeated 1,048,576 times (or until 1MB filled)

   Ku = hash(buf)  -- MD5 produces 16 bytes, SHA produces 20 bytes

2. Key Localization (Kul generation):

   Kul = hash(Ku || engineID || Ku)

   Where:
   - || means concatenation
   - engineID is the authoritative engine's ID
   - hash is MD5 or SHA-1 depending on auth protocol
```

### Example (MD5):
```
Password: "mypassword"
EngineID: 0x80001f88034e4c4d4e5353494d
Buffer: "mypassword" repeated to 1MB
Ku = MD5(buffer) = [16 bytes]
Kul = MD5(Ku || engineID || Ku) = [16 bytes]
```

---

## Authentication Process

### Generating Authentication Parameters

```
1. Set msgAuthenticationParameters to 12 zero bytes initially
2. Build complete SNMPv3 message with zeros
3. Calculate HMAC over entire message using Kul
4. Take first 12 bytes of HMAC result
5. Replace the 12 zero bytes with calculated HMAC
6. Send message
```

### Verifying Received Message

```
1. Extract msgAuthenticationParameters (12 bytes)
2. Replace those 12 bytes with zeros in the message
3. Calculate HMAC over modified message using Kul
4. Compare first 12 bytes of calculated HMAC with extracted parameters
5. If match: authenticated, else: reject
```

---

## Engine ID

### Format
- **Minimum length**: 5 bytes
- **Maximum length**: 32 bytes
- **Typical length**: 9-17 bytes

### Structure (RFC 3411)
```
Byte 0-3: Enterprise ID (first bit 1 for private, 0 for IANA)
Byte 4: Format (1-6)
Bytes 5+: Format-specific data

Common formats:
- Format 1: IPv4 address (4 bytes)
- Format 2: IPv6 address (16 bytes)
- Format 3: MAC address (6 bytes)
- Format 4: Text (admin defined)
- Format 5: Octets (admin defined)
- Format 6: Reserved
```

### Example Engine IDs
```
0x80001f88034e4c4d4e5353494d  (17 bytes)
0x8000000001020304           (9 bytes)
```

---

## Three-Phase Communication

SNMPv3 requires multiple round trips for initial setup:

### Phase 1: Engine ID Discovery (if unknown)
```
Request:
- msgAuthoritativeEngineID: empty (0 bytes)
- msgUserName: empty
- msgAuthenticationParameters: empty
- msgFlags: 0x04 (reportable)

Response:
- Returns usmStatsUnknownEngineIDs report
- Contains authoritative engine ID
```

### Phase 2: Time Synchronization
```
Request:
- msgAuthoritativeEngineID: from Phase 1
- msgAuthoritativeEngineBoots: 0
- msgAuthoritativeEngineTime: 0
- msgUserName: actual username
- msgAuthenticationParameters: 12 bytes HMAC
- msgFlags: 0x05 (auth + reportable)

Response:
- Returns usmStatsNotInTimeWindows report (or success)
- Contains engine boots and time
```

### Phase 3: Actual Request
```
Request:
- msgAuthoritativeEngineID: from Phase 1
- msgAuthoritativeEngineBoots: from Phase 2
- msgAuthoritativeEngineTime: from Phase 2 (adjusted)
- msgUserName: actual username
- msgAuthenticationParameters: 12 bytes HMAC
- msgFlags: 0x01 (auth only, no reportable for GET)
- PDU: actual GET/SET/etc request

Response:
- Normal SNMP response with data
```

---

## Time Window Validation

SNMPv3 requires messages to be within a time window to prevent replay attacks.

### Requirements (RFC 3414)
- **Engine Boots**: Must match or be greater
- **Engine Time**: Must be within ±150 seconds of agent's current time
- **Not in Time Window**: Reject and send usmStatsNotInTimeWindows

### Client Responsibilities
1. Track engine boots and time from responses
2. Update local time estimate for each response
3. Adjust time for request delays
4. Re-sync if time window expires

---

## Implementation Components

### New Namespaces

```
kouvas.snmp4clj/
├── v3/
│   ├── message.clj          ; v3 message structure
│   ├── usm.clj              ; User-based Security Model
│   ├── engine.clj           ; Engine ID management
│   ├── auth.clj             ; HMAC authentication
│   ├── crypto.clj           ; Key localization algorithms
│   └── time_sync.clj        ; Time window management
```

### Key Data Structures

```clojure
;; Engine state
{:engine-id [bytes]
 :boots 123
 :time 456789
 :last-updated (Instant)
 :username "user"
 :auth-protocol :md5  ; or :sha
 :auth-key [bytes]}   ; Localized key

;; v3 Request parameters
{:version :snmp/v3
 :security-level :auth-no-priv
 :username "myuser"
 :auth-protocol :md5
 :auth-password "mypassword"
 :context-engine-id nil  ; Usually same as authoritative
 :context-name ""
 :engine-id nil      ; Auto-discover if nil
 ...}
```

---

## Java Crypto Usage (javax.crypto)

Zero external dependencies - use built-in Java crypto:

```clojure
(import '[javax.crypto Mac]
        '[javax.crypto.spec SecretKeySpec]
        '[java.security MessageDigest])

;; HMAC-MD5
(def mac (Mac/getInstance "HmacMD5"))
(.init mac (SecretKeySpec. key-bytes "HmacMD5"))
(.doFinal mac message-bytes)

;; MD5 hash
(def md (MessageDigest/getInstance "MD5"))
(.digest md data)
```

---

## Testing Strategy

1. **Unit Tests**
   - Key localization (known test vectors)
   - HMAC calculation
   - Message encoding/decoding
   - Time window validation

2. **Integration Tests**
   - Engine discovery
   - Time synchronization
   - Authenticated GET request
   - Invalid credentials rejection

3. **Known Test Vectors** (RFC 3414)
   - Use official test vectors for key localization
   - Verify HMAC calculations

---

## Migration Path

### Phase 1: Core v3 Message Structure ✓
- Encode/decode v3 messages
- HeaderData, USM parameters, ScopedPDU

### Phase 2: USM Implementation ✓
- Engine ID discovery
- Key localization (password → key)
- HMAC authentication

### Phase 3: Time Synchronization ✓
- Track engine boots/time
- Time window validation
- Auto re-sync

### Phase 4: Integration ✓
- Update snmp-request to handle v3
- Auto-discover engine ID
- Handle 3-phase protocol transparently

### Phase 5: Testing & Polish ✓
- Comprehensive tests
- Error handling
- Documentation

---

## API Design

### User-facing API (Goal)

```clojure
;; Simplest usage (auto-discovery)
(snmp/snmp-request
  {:version :snmp/v3
   :security-level :auth-no-priv
   :host "192.168.1.1"
   :username "admin"
   :auth-protocol :md5
   :auth-password "secret123"
   :oids ["1.3.6.1.2.1.1.1.0"]})

;; Advanced usage (manual engine ID)
(snmp/snmp-request
  {:version :snmp/v3
   :security-level :auth-no-priv
   :host "192.168.1.1"
   :username "admin"
   :auth-protocol :sha
   :auth-password "secret123"
   :engine-id [0x80 0x00 0x1f 0x88 0x03 ...]
   :engine-boots 5
   :engine-time 123456
   :oids ["1.3.6.1.2.1.1.1.0"]})
```

Library handles:
- ✅ Engine ID discovery (if not provided)
- ✅ Time synchronization
- ✅ Key localization
- ✅ HMAC calculation
- ✅ Message construction

---

## References

- **RFC 3411**: SNMP Management Framework
- **RFC 3412**: Message Processing and Dispatching
- **RFC 3414**: User-based Security Model (USM)
- **RFC 3416**: Protocol Operations (v3)
- **RFC 3826**: AES encryption (for future authPriv)

---

## Estimated Effort

| Component | Complexity | Estimate |
|-----------|------------|----------|
| Message structure | Medium | 3-4 hours |
| USM parameters | Low | 2 hours |
| Key localization | Medium | 3-4 hours |
| HMAC auth | Low | 2 hours |
| Engine discovery | Medium | 3 hours |
| Time sync | Medium | 3 hours |
| Integration | Medium | 3-4 hours |
| Testing | High | 4-5 hours |
| **Total** | | **~25 hours** |

Spread over 1-2 weeks part-time, this is very achievable!
