Splunk Sysmon Baseline Visibility Upgrade

Project Summary
This project upgrades Windows endpoint visibility by installing Sysmon with a default configuration and ingesting its logs into Splunk. The goal is to validate improved telemetry coverage across key attacker behaviors that were previously missed using native audit policies.

Cybersecurity Battlefield Alignment

Strengthens Host Operating System layer, specifically:

Process Execution

Command-Line Logging

Background Services (parent-child relationships)

Enhances the Visibility and Telemetry Layer through:

Sysmon logs captured from Microsoft-Windows-Sysmon/Operational

Splunk-based SIEM correlation and triage

Setup Summary

Installed Sysmon using: Sysmon64.exe -accepteula -i

Confirmed Event ID 1 (Process Create) and other logs were active in Event Viewer

Configured Splunk input for Sysmon with:

Channel: Microsoft-Windows-Sysmon/Operational

Index: main

Format: XML enabled

Restarted Splunk to validate ingestion

Tested Attacker Behaviors and Visibility Results

Obfuscated PowerShell command using base64-encoded Start-Process notepad.exe

Result: Captured via Sysmon Event ID 1 with full command-line visibility

Scheduled Task created using schtasks /create /tn Updater2 /tr notepad.exe

Result: Logged via Sysmon with full arguments and metadata

Privilege enumeration using whoami /priv and icacls C:\Windows

Result: Captured both commands with elevated context and process details

RDP connection attempt using mstsc /v:192.168.56.102

Result: Logged as process creation from PowerShell with full command-line

SMB share access attempt using net use \\192.168.56.102\C$

Result: Captured as process creation with command-line and user info

Localhost Nmap scan using:

nmap -sS -Pn -T4 -F 127.0.0.1

nmap -sV -T4 127.0.0.1

Result: Both executions logged via Sysmon with complete process lineage

Key Outcomes

Default Sysmon config captured attacker behaviors missed by Windows Event ID 4688

Provided command-line, parent-child, and user context data for each process

Enabled high-fidelity Splunk triage for early-stage attacks

Showed immediate gains in visibility with minimal configuration effort

Lessons Learned

Native audit policy was insufficient for detecting encoded PowerShell and privilege inspection

Sysmon is a critical upgrade for defender visibility when EDR is not present

Even without tuning, Sysmon filled critical gaps in process telemetry

Future projects should build on this baseline with enhanced Sysmon configurations (e.g., SwiftOnSecurity)


