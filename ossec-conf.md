## Ossec Conf:

```bash
	nano /var/ossec/etc/ossec.conf
```

```bash
<integration>
  <name>custom-opencti</name>
  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event15,sysmon_event22,sysmon_event23,sysmon_event24,sysmon_event25,sysmon_eid3_detections,sysmon_eid22_detections,syscheck_file,syscheck_entry_added,syscheck_entry_modified,syscheck_registry,ids,osquery,osquery_file,audit_command,auditd</group>
  <alert_format>json</alert_format>
  <api_key>flgrn_octi_tkn__xGFnVE_5n8RaUoOoRi9wwiq7V4YdeJjIAW8EGn025O-Loc0ZJ3kk5ZUgcedebN3</api_key>
  <hook_url>http://10.234.236.25:8080/graphql</hook_url>
</integration>

```

---

```bash
<ossec_config>
  <integration>
    <name>custom-opencti</name>
    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event15,sysmon_event22,sysmon_event23,sysmon_event24,sysmon_event25,sysmon_eid3_detections,sysmon_eid22_detections,syscheck_file,syscheck_entry_added,syscheck_entry_modified,syscheck_registry,ids,osquery,osquery_file,audit_command,auditd</group>
    <alert_format>json</alert_format>
    <api_key>flgrn_octi_tkn__xGFnVE_5n8RaUoOoRi9wwiq7V4YdeJjIAW8EGn025O-Loc0ZJ3kk5ZUgcedebN3</api_key>
    <hook_url>http://192.168.31.155/graphql</hook_url>
  </integration>
</ossec_config>
```
