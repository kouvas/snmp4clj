#!/bin/bash
podman build -t snmpd .
podman run -d -p 161:161/udp --name snmpd-container snmpd