## Local Rules

```bash
	nano /var/ossec/etc/rules/local_rules.xml
```

```bash
<!-- ============================================================
     Wazuh Local Rules — OpenCTI Threat Intel Integration
     Covers: OpenCTI alerts + Linux auditd targeted binary monitoring
     Author: Ramkumar 2026, ITFORTRESS
     Fix v3: Rule 100499 — SYSCALL-only fallback (audit group, no execve)
             Catches ping/curl/wget etc. when Wazuh rule 80700 fires
             (SYSCALL-only, no EXECVE record correlated yet).
             audit.command + audit.exe fields used instead of execve.a0.
     ============================================================ -->

<!-- ── OpenCTI Base Rules ─────────────────────────────────────── -->
<group name="threat_intel,">

  <rule id="100210" level="10">
    <field name="integration">^opencti$</field>
    <description>OpenCTI</description>
    <group>opencti,</group>
  </rule>

  <rule id="100211" level="5">
    <if_sid>100210</if_sid>
    <field name="opencti.error">.+</field>
    <description>OpenCTI: Failed to connect to API</description>
    <options>no_full_log</options>
    <group>opencti,opencti_error,</group>
  </rule>

  <rule id="100212" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^indicator_pattern_match$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100213" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_with_indicator$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100214" level="10">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_with_related_indicator$</field>
    <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100215" level="10">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^indicator_partial_pattern_match$</field>
    <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

  <rule id="100216" level="12">
    <if_sid>100210</if_sid>
    <field name="opencti.event_type">^observable_without_indicator$</field>
    <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_alert,</group>
  </rule>

</group>

<!-- ── Linux auditd Targeted Binary Rules ─────────────────────── -->
<!--
  TWO base rules cover the two event shapes Wazuh produces:

  Rule 100499 — SYSCALL-only (no EXECVE record correlated yet)
    Wazuh rule 80700 fires first with group="audit", level=0 (suppressed).
    Our rule 100499 chains off group="audit" + audit.key=command_monitor
    and re-tags with audit_command so the integration script fires.
    Uses audit.command field (e.g. "ping") — no execve.a0 available.

  Rule 100500 — Full correlated event (SYSCALL + EXECVE correlated)
    Wazuh rules 80700→80792 correlate SYSCALL+EXECVE and produce execve.a0.
    Our rule 100500 chains off group="audit_command" + audit.key=command_monitor.
    Child rules 100501–100510 match on execve.a0 for specific binaries.
-->
<group name="linux,auditd,">

  <!-- ── SYSCALL-only fallback (no execve dict) ── -->
  <rule id="100499" level="5">
    <if_group>audit</if_group>
    <field name="audit.key">^command_monitor$</field>
    <field name="audit.command" type="pcre2">(?:^|/)(?:curl|wget|ping|ping6|nslookup|dig|host|nmap|nc|netcat|ncat|telnet|ftp|tftp|scp|ssh|socat|tcpdump|openssl|python[0-9.]*|php[0-9.]*|perl|bash|sh|zsh|ksh)$</field>
    <description>Linux: Monitored binary executed (SYSCALL, auditd): $(audit.command) [exe: $(audit.exe)]</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <!-- ── Full correlated event (execve available) ── -->
  <rule id="100500" level="3">
    <if_group>audit_command</if_group>
    <field name="audit.key">^command_monitor$</field>
    <description>Linux: Monitored binary executed (auditd): $(audit.execve.a0)</description>
    <group>linux,auditd,audit_command,</group>
  </rule>

  <rule id="100501" level="10">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:curl|wget)$</field>
    <description>Linux: Download tool executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100502" level="8">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:nmap|nslookup|dig|host)$</field>
    <description>Linux: Network recon tool executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100503" level="12">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:nc|netcat|ncat|socat)$</field>
    <description>Linux: Potential reverse shell tool executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100504" level="10">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:ftp|tftp|scp)$</field>
    <description>Linux: File transfer tool executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100505" level="6">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)ssh$</field>
    <description>Linux: SSH outbound connection: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100506" level="6">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:python[0-9.]*|php[0-9.]*|perl)$</field>
    <description>Linux: Scripting language executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,</group>
  </rule>

  <rule id="100507" level="6">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:bash|sh|zsh|ksh)$</field>
    <description>Linux: Shell spawned via monitored binary: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,</group>
  </rule>

  <rule id="100508" level="8">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)(?:tcpdump|openssl)$</field>
    <description>Linux: Suspicious utility executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100509" level="5">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)ping6?$</field>
    <description>Linux: Ping executed: $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

  <rule id="100510" level="10">
    <if_sid>100500</if_sid>
    <field name="audit.execve.a0" type="pcre2">(?:^|/)telnet$</field>
    <description>Linux: Telnet executed (plaintext protocol): $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>linux,auditd,audit_command,network_tools,</group>
  </rule>

</group>

<!-- ── High-score OpenCTI IOC Escalation ─────────────────────── -->
<group name="opencti,opencti_high,">

  <rule id="100221" level="14">
    <if_group>opencti_alert</if_group>
    <field name="opencti.indicator.x_opencti_score" type="pcre2">^(7[0-9]|8[0-9]|9[0-9]|100)$</field>
    <description>OpenCTI Critical: Malicious IoC [Score: $(opencti.indicator.x_opencti_score)] - Target: $(opencti.query_values)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_high,</group>
  </rule>

  <rule id="100222" level="14">
    <if_group>opencti_alert</if_group>
    <field name="opencti.x_opencti_score" type="pcre2">^(7[0-9]|8[0-9]|9[0-9]|100)$</field>
    <description>OpenCTI Critical: Malicious IoC [Score: $(opencti.x_opencti_score)] - Target: $(opencti.query_values)</description>
    <options>no_full_log</options>
    <group>opencti,opencti_high,</group>
  </rule>

</group>
```
