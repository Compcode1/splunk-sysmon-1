The integration of Sysmon into the Windows host significantly enhanced our visibility across multiple attack stages simulated in this project. By comparing the Sysmon-generated telemetry (e.g., Event ID 1 for process creation) against prior native Windows Security logs, we confirmed several key improvements:

Enhanced Fidelity: Sysmon delivered granular details including full command-line arguments, image hashes, parent process relationships, and user context — critical elements that were previously missing or only partially available.

Telemetry Gap Closure: Actions such as obfuscated PowerShell use, scheduled task persistence, Nmap scanning, and RDP/SMB probing were captured more reliably and with greater forensic clarity than before.

Remaining Gaps: Despite Sysmon’s value, certain behavioral detections — like privilege elevation attempts that do not spawn new processes — still require complementary telemetry (e.g., ETW-based logging or EDR solutions).

Our final assessment confirms that Sysmon is a necessary layer in any serious detection engineering strategy, particularly when operating without commercial EDR or NDR tools. Based on these findings, we recommend the following for future projects:

Use a vetted, minimal-noise Sysmon configuration (e.g., SwiftOnSecurity base + custom tuning) to ensure balance between coverage and log volume.

Maintain rigorous version control of sysmon_config.xml alongside analysis notebooks in GitHub for reproducibility.
