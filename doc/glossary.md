# SNMP Glossary

## Table of Contents

- [Protocol Terms](#protocol-terms)
  - [Agent](#agent)
  - [ASN.1](#asn1)
  - [BER](#ber)
  - [Community String](#community-string)
  - [Manager](#manager)
  - [MIB](#mib)
  - [OID](#oid)
  - [PDU](#pdu)
  - [SMI](#smi)
  - [SNMP](#snmp)
  - [Variable Binding](#variable-binding)
- [Data Types](#data-types)
  - [INTEGER](#integer)
  - [OCTET STRING](#octet-string)
  - [NULL](#null)
  - [OBJECT IDENTIFIER](#object-identifier)
  - [SEQUENCE](#sequence)
  - [IpAddress](#ipaddress)
  - [Counter32](#counter32)
  - [Gauge32](#gauge32)
  - [TimeTicks](#timeticks)
  - [Opaque](#opaque)
  - [Counter64](#counter64)
- [Encoding Terms](#encoding-terms)
  - [Constructed](#constructed)
  - [Definite-length](#definite-length)
  - [Implicit Tag](#implicit-tag)
  - [Primitive](#primitive)
  - [Tag](#tag)
  - [TLV](#tlv)
  - [Universal Tag](#universal-tag)
- [SNMP Operations](#snmp-operations)
  - [GET](#get)
  - [GETNEXT](#getnext)
  - [GETBULK](#getbulk)
  - [SET](#set)
  - [RESPONSE](#response)
  - [TRAP](#trap)
  - [INFORM](#inform)

## Protocol Terms

### Agent
An SNMP entity that provides access to management information

### ASN.1
Abstract syntax one provides a way to describe data that's independent of machine-specific encodings.
It defines both the abstract syntax (what the data looks like) and transfer syntax (how it's encoded for transmission).

### BER
Basic Encoding Rules - rules for encoding ASN.1 data structures

### Community String
A password-like string used for authentication in SNMPv1/v2c

### Manager
An SNMP entity that requests management information from agents

### MIB
Management Information Base - a collection of managed objects

### OID
Object Identifier Tree is the hierarchical naming scheme that provides **globally unique** identifiers for all
managed objects. Each node in the tree represents a registration authority or a specific managed object.

Common OID constants: 
``` 
iso        [1]
org        [1 3]
dod        [1 3 6]
internet   [1 3 6 1]
mgmt       [1 3 6 1 2]
mib-2      [1 3 6 1 2 1]
system     [1 3 6 1 2 1 1]
interfaces [1 3 6 1 2 1 2]
```
### PDU
Protocol Data Unit - the data structure used in SNMP messages

### SMI
Defines how management information is structured and organized in SNMP. It's the "grammar" and "syntax rules" for
defining network management data.


### SNMP
Simple Network Management Protocol

### Variable Binding
A pairing of an OID with its associated value

## Data Types

### INTEGER
32-bit signed integer (-2^31 to 2^31-1) - ASN.1 tag: 0x02

### OCTET STRING
Arbitrary byte string - ASN.1 tag: 0x04

### NULL
No value (used in GET requests) - ASN.1 tag: 0x05

### OBJECT IDENTIFIER
Hierarchical object identifier - ASN.1 tag: 0x06

### SEQUENCE
Ordered collection of values - ASN.1 tag: 0x30

### IpAddress
4-byte IPv4 address - ASN.1 tag: 0x40

### Counter32
32-bit counter (wraps at max) - ASN.1 tag: 0x41

### Gauge32
32-bit gauge (doesn't wrap) - ASN.1 tag: 0x42

A Gauge in SNMP represents a non-negative integer value that can increase or decrease but has a defined maximum value it cannot exceed. When it reaches its maximum, it stays at that maximum rather than wrapping around to zero.

Key Characteristics:

Non-wrapping behavior: Unlike a Counter, when a Gauge reaches its maximum value (typically 2^32 - 1 for a 32-bit Gauge), it "pegs" or "saturates" at that maximum value rather than rolling over to zero.

Bidirectional: Gauge values can go up or down. They represent instantaneous measurements or current states, not cumulative totals.

Absolute values: A Gauge represents the current value of something at the time it's read, not a rate or accumulated count.

Common Examples:

Interface Utilization: Current bandwidth usage on a network interface (can go up or down based on traffic)

Temperature Readings: Current temperature of a device component (fluctuates based on conditions)

Memory Usage: Current amount of RAM being used (increases and decreases as processes allocate/free memory)

Active Connections: Number of currently active TCP connections (goes up as connections are established, down as they're closed)

Queue Depth: Current number of packets in a buffer (varies based on traffic patterns)

Practical Difference from Counter:
```
Counter behavior:
Value: 100 → 200 → 300 → 4294967295 → 0 → 1 → 2 (wraps)

Gauge behavior:
Value: 100 → 200 → 300 → 4294967295 → 4294967295 → 4294967295 (pegs)
```
Why This Matters:

Monitoring Systems: Network monitoring tools need to know whether a value can wrap (Counter) or will peg (Gauge) to correctly interpret trends and set up alerting thresholds.

Alerting Logic: You might set an alert for when a Gauge value exceeds 80% of maximum, knowing it won't suddenly jump to zero and create false recovery notifications.

Graphing: Time-series graphs handle Gauges differently than Counters since there's no need to account for counter rollovers when calculating rates or derivatives.
The "don't wrap" characteristic is crucial for values that represent current state rather than accumulated totals, ensuring that monitoring systems can reliably track instantaneous measurements without worrying about rollover artifacts.

### TimeTicks
Time in hundredths of seconds - ASN.1 tag: 0x43

### Opaque
Arbitrary ASN.1 value - ASN.1 tag: 0x44

### Counter64
64-bit counter (SNMPv2 only) - ASN.1 tag: 0x46

## Encoding Terms

### Constructed
An encoding that contains other encodings

### Definite-length
Length is explicitly specified in the encoding

### Implicit Tag
A context-specific tag that replaces the universal tag

### Primitive
An encoding of a simple value (not constructed)

### Tag
Identifies the type of the encoded value

### TLV
Type-Length-Value encoding structure

### Universal Tag
Standard ASN.1 type identifier

## SNMP Operations

### GET
Retrieve the value of one or more variables

### GETNEXT
Retrieve the next variable in the MIB tree

### GETBULK
Retrieve multiple variables efficiently (v2 only)

### SET
Modify the value of one or more variables

### RESPONSE
Reply to any request operation

### TRAP
Unacknowledged notification from agent to manager

### INFORM
Acknowledged notification (v2 only)
