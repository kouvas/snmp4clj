# Understanding ASN.1 and BER Encoding

---

## What is ASN.1?

**ASN.1 (Abstract Syntax Notation One)** is a standard for describing data structures in a platform-independent way. Think of it as a universal language for describing how data should be structured, regardless of the programming language or system.

- More compact (binary encoding)
- Strongly typed
- Used in protocols like SNMP, X.509 certificates, LDAP

---

## BER Encoding: The TLV Structure

**BER (Basic Encoding Rules)** is one way to encode ASN.1 data into bytes. It uses a **TLV (Type-Length-Value)** structure:

``` 
┌──────┐     ┌────────┐     ┌───────┐
│ Type │ --> │ Length │ --> │ Value │
└──────┘     └────────┘     └───────┘
1+ bytes     1+ bytes       N bytes
```


- **Type**: 1+ bytes (What kind of data)
- **Length**: 1+ bytes (How many bytes of data)
- **Value**: N bytes (The actual data)

---

## Common ASN.1 Types

| Type            | Tag (Hex) | Tag (Binary) | Description      |
|-----------------|-----------|--------------|------------------|
| INTEGER         | 0x02      | 00000010     | Whole numbers    |
| OCTET STRING    | 0x04      | 00000100     | Byte arrays      |
| NULL            | 0x05      | 00000101     | No value         |
| OBJECT IDENTIFIER | 0x06    | 00000110     | OIDs (like 1.3.6.1) |
| SEQUENCE        | 0x30      | 00110000     | Ordered collection |

---

## Example 1: Encoding an Integer (42)

**Value to encode:** 42

**Process:**
1. Type: INTEGER = 0x02
2. Length: 42 fits in 1 byte, so length = 1 = 0x01
3. Value: 42 = 0x2A

**BER Encoding:**
``` 
┌──────┬────────┬──────────┐
│ 0x02 │  0x01  │   0x2A   │
├──────┼────────┼──────────┤
│ Type │ Length │ Value(42)│
└──────┴────────┴──────────┘
```

---

## Example 2: Encoding a String ("Hello")

**Value to encode:** "Hello"

**Process:**
1. Type: OCTET STRING = 0x04
2. Length: "Hello" = 5 bytes = 0x05
3. Value: ASCII bytes for "Hello"

**BER Encoding:**
``` 
┌──────┬────────┬──────┬──────┬──────┬──────┬──────┐
│ 0x04 │  0x05  │ 0x48 │ 0x65 │ 0x6C │ 0x6C │ 0x6F │
├──────┼────────┼──────┼──────┼──────┼──────┼──────┤
│ Type │ Length │  'H' │  'e' │  'l' │  'l' │  'o' │
└──────┴────────┴──────┴──────┴──────┴──────┴──────┘
```


---

## Length Encoding Rules

BER uses two forms for encoding length:

### 1. Short Form (1 byte): For lengths 0-127
``` 
┌──────┐
│ 0x45 │  Length = 69
└──────┘
```

### 2. Long Form (2+ bytes): For lengths ≥ 128
- First byte: `0x80 | number_of_length_bytes`
- Following bytes: The actual length in big-endian format

**Example: Length = 300 (0x012C)**
``` 
┌──────┬──────┬──────┐
│ 0x82 │ 0x01 │ 0x2C │
├──────┼──────┼──────┤
│ Long │ High │ Low  │
│ form │ byte │ byte │
└──────┴──────┴──────┘
```
0x82 = 10000010 (MSB=1 means long form, remaining bits = 2 length bytes)

**Examples of Different Header Sizes:**

``` 
Length 127:      30 7F ...              (2 bytes: tag + length)
Length 128:      30 81 80 ...           (3 bytes: tag + long form marker + 1 length byte)
Length 255:      30 81 FF ...           (3 bytes)
Length 256:      30 82 01 00 ...        (4 bytes: tag + marker + 2 length bytes)
Length 65535:    30 82 FF FF ...        (4 bytes)
Length 65536:    30 83 01 00 00 ...     (5 bytes: tag + marker + 3 length bytes)
Length 16777215: 30 83 FF FF FF ...     (5 bytes)
Length 16777216: 30 84 01 00 00 00 ...  (6 bytes: tag + marker + 4 length bytes)
```


**Maximum Length Supported:**
- `0x81`: 1 length byte → max 255 bytes (2^8 - 1)
- `0x82`: 2 length bytes → max 65,535 bytes (2^16 - 1)
- `0x83`: 3 length bytes → max 16,777,215 bytes (~16 MB)
- `0x84`: 4 length bytes → max 4,294,967,295 bytes (~4 GB)
- `0x85`: 5 length bytes → max 1,099,511,627,775 bytes (~1 TB)
- `0xFF`: 127 length bytes → max 2^(127×8) - 1 bytes (astronomically large)

**Practical Limits:**
- SNMPv1/v2c typically limited to **65,535 bytes** (fits in UDP)
- Many implementations limit to **1,472 bytes** (Ethernet MTU minus headers)
- SNMPv3 can use TCP for larger messages

**Common Real-World Scenarios:**

- Most SNMP messages: < 1,500 bytes (2-3 byte headers)
- Large GetBulk responses: might reach 65,535 bytes (4 byte headers)
- SNMP over TCP: could theoretically go larger

**When You'll See Longer Headers:**
- GetBulk operations requesting many OIDs
- SNMP tables with thousands of rows
- Large OCTET STRING values
- SNMPv3 with encryption adding overhead
- SNMP over TCP removing UDP size constraints

---

## OID Encoding: Special Rules

**OID Example:** 1.3.6.1.2.1 (common SNMP OID prefix)

**Special encoding rules:**
1. First two numbers are combined: (first × 40) + second
2. Each subsequent number encoded with 7-bit chunks
3. MSB=1 means "more bytes follow", MSB=0 means "last byte"

### Understanding the First Two Numbers

The first two components of an OID are encoded together as a single byte to save space. This is a design decision from the ASN.1 standard based on OID constraints:
- First number can only be 0, 1, or 2
- If first is 0 or 1, second must be 0-39
- If first is 2, second can be any value

**The formula: (first × 40) + second**

This creates "slots" of 40 values:
- 0-39: OIDs starting with 0.x (0.0 through 0.39)
- 40-79: OIDs starting with 1.x (1.0 through 1.39)
- 80+: OIDs starting with 2.x (2.0, 2.1, 2.2, ...)

**Examples:**
- 0.5 → (0 × 40) + 5 = 5
- 1.3 → (1 × 40) + 3 = 43 = 0x2B
- 2.5 → 80 + 5 = 85 = 0x55
- 2.999 → 80 + 999 = 1079 (needs multi-byte encoding)

### Understanding MSB (Most Significant Bit)

**MSB** stands for **Most Significant Bit** - the leftmost bit in a byte.
``` 
[MSB][x][x][x][x][x][x][LSB]
  ↑                      ↑
Most Significant    Least Significant
```

In OID encoding, the MSB is used as a "continuation flag":
- **MSB = 1**: More bytes follow for this number
- **MSB = 0**: This is the last byte for this number

**Example: Encoding the number 311**

311 in binary: `100110111` (9 bits)

Step 1: Split into 7-bit chunks (right to left):
``` 
  10  0110111
  ^^  ^^^^^^^
2 bits  7 bits
```
Step 2: Encode each chunk:
``` 
[1][0000010] = 0x82    [0][0110111] = 0x37
MSB=1 (more)           MSB=0 (last)
Value=2                Value=55
```

To decode: (2 × 128) + 55 = 256 + 55 = 311

**More Examples:**
- **127:** Fits in 7 bits → `[0]1111111` = 0x7F (one byte)
- **128:** Needs 8 bits → `[1]0000001 [0]0000000` = 0x81 0x00
- **16384:** `[1]0000001 [1]0000000 [0]0000000` = 0x81 0x80 0x00

**Complete encoding process for 1.3.6.1.2.1:**
- 1.3 → (1 × 40) + 3 = 43 = 0x2B
- 6 → 0x06
- 1 → 0x01
- 2 → 0x02
- 1 → 0x01
```
┌──────┬────────┬──────┬──────┬──────┬──────┬──────┐
│ 0x06 │  0x05  │ 0x2B │ 0x06 │ 0x01 │ 0x02 │ 0x01 │
├──────┼────────┼──────┼──────┼──────┼──────┼──────┤
│ OID  │ Length │ 1.3  │  6   │  1   │  2   │  1   │
└──────┴────────┴──────┴──────┴──────┴──────┴──────┘
```

## PDU Encoding: SNMP Protocol Data Units

**PDU (Protocol Data Unit)** is the message format used in SNMP communications. SNMP PDUs are encoded as ASN.1 SEQUENCE structures with special type tags.

### SNMP PDU Types

| PDU Type       | Tag (Hex) | Tag (Binary) | Description                       |
|----------------|-----------|--------------|-----------------------------------|
| GetRequest     | 0xA0      | 10100000     | Request specific values           |
| GetNextRequest | 0xA1      | 10100001     | Request next value in MIB         |
| GetResponse    | 0xA2      | 10100010     | Response to any request           |
| SetRequest     | 0xA3      | 10100011     | Set specific values               |
| Trap (v1)      | 0xA4      | 10100100     | Unsolicited notification          |
| GetBulkRequest | 0xA5      | 10100101     | Request multiple values (v2c)     |
| InformRequest  | 0xA6      | 10100110     | Acknowledged notification (v2c)   |
| Trap (v2)      | 0xA7      | 10100111     | Unacknowledged notification (v2c) |
| Report         | 0xA8      | 10101000     | Internal communication (v3)       |

### PDU Tag Structure Analysis

SNMP PDU tags use ASN.1 context-specific constructed tags:
``` 
1 0 1 0 0 x x x
↑ ↑ ↑     ↑
Class  Constructed  Tag number
```

- **Bits 7-6 (10):** Context-specific class
- **Bit 5 (1):** Constructed (contains other TLV structures)
- **Bits 4-0:** Tag number (0-8 for different PDU types)

### PDU Structure
```
PDU ::= SEQUENCE {
  request-id      INTEGER,
  error-status    INTEGER,
  error-index     INTEGER,
  variable-bindings VarBindList
}
```
### Example: Real Network Capture of GetRequest PDU

**Requesting system description (OID: 1.3.6.1.2.1.1.1.0)**

**Complete encoded SNMPv2c GetRequest message:**
``` 
30 29                    -- SEQUENCE (41 bytes) SNMP message
  02 01 01               -- INTEGER version=1 (SNMPv2c)
  04 06 70 75 62 6C 69 63 -- OCTET STRING "public"
  A0 1C                  -- GetRequest PDU (28 bytes)
    02 04 0B 35 F2 22    -- INTEGER request-id=188019234
    02 01 00             -- INTEGER error-status=0
    02 01 00             -- INTEGER error-index=0
    30 0E                -- SEQUENCE variable-bindings (14 bytes)
      30 0C              -- SEQUENCE VarBind (12 bytes)
        06 08 2B 06 01 02 01 01 01 00  -- OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        05 00            -- NULL value
```

**Hexdump representation:**
``` 
00000000  30 29 02 01 01 04 06 70 75 62 6C 69 63 A0 1C 02  |0).....public...|
00000010  04 0B 35 F2 22 02 01 00 02 01 00 30 0E 30 0C 06  |..5."......0.0..|
00000020  08 2B 06 01 02 01 01 01 00 05 00                 |.+.........|
```
## Example 3: Long Form Length Encoding - SNMP GET with Multiple OIDs

**Real-world SNMP GET Request with 9 OIDs**

This example demonstrates how BER uses long form length encoding when the content exceeds 127 bytes.

**Key observation: This message uses long form length encoding!**
- Total message: 157 bytes
- SEQUENCE header: 3 bytes (tag + length-of-length + length)
- SEQUENCE content: 154 bytes
- Since 154 > 127, we must use long form length encoding

### Outer SEQUENCE (SNMP Message header)
``` 
┌──────┬──────────────┬──────────────┐
│ 0x30 │     0x81     │     0x9A     │
├──────┼──────────────┼──────────────┤
│ SEQ  │ Long form    │ Length = 154 │
│      │ 1 length byte│              │
└──────┴──────────────┴──────────────┘
```

**Understanding 0x81 0x9A:**
- **0x81:** Binary = 10000001
    - MSB (bit 7) = 1: Long form indicator
    - Bits 6-0 = 0000001: One length byte follows
- **0x9A:** The actual length = 154 decimal

### The 9 OIDs Being Requested

Pattern for each VarBind (14 bytes each):
``` 
30 0C                    -- SEQUENCE (12 bytes)
06 08                    -- OID type, 8 bytes length
2B 06 01 02 01 01 XX 00  -- OID 1.3.6.1.2.1.1.X.0
05 00                    -- NULL value
```
The 9 OIDs requested (all under 1.3.6.1.2.1.1):
1. 1.3.6.1.2.1.1.6.0 (sysLocation)
2. 1.3.6.1.2.1.1.3.0 (sysUpTime)
3. 1.3.6.1.2.1.1.4.0 (sysContact)
4. 1.3.6.1.2.1.1.5.0 (sysName)
5. 1.3.6.1.2.1.1.1.0 (sysDescr) - repeated 5 times

## Complex Example: SNMP Message Structure

**Nested TLV structure visualization:**
``` 
SNMP Message
├─ SEQUENCE (Message)
│  ├─ INTEGER: version (0, 1, or 3)
│  ├─ OCTET STRING: community ("public")
│  └─ PDU (GetRequest/GetResponse/etc.)
│     ├─ INTEGER: request-id
│     ├─ INTEGER: error-status
│     ├─ INTEGER: error-index
│     └─ SEQUENCE: variable-bindings
│        └─ SEQUENCE: VarBind
│           ├─ OID: name
│           └─ ANY: value
```