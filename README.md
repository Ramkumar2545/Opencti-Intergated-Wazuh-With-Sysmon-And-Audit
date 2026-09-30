# OpenCTI Integrated Wazuh — With Sysmon And Audit

Step-by-step notes for wiring **OpenCTI** (threat intel) into **Wazuh** (SIEM), with Windows
endpoints monitored through **Sysmon** and Linux endpoints monitored through **auditd**.



## Contents / step-by-step order

| Step | File | What it covers |
|---|---|---|
| 1 | [`opencti-installation-core-dependencies.md`](opencti-installation-core-dependencies.md) | Hardware sizing, software prerequisites, Docker install, `vm.max_map_count`, core service resource shares, network/port requirements, cloning the OpenCTI Docker repo, `.env` setup, `docker compose up -d --build` |
| 2 | [`phase3-agent-group-windows.md`](phase3-agent-group-windows.md) | Windows agent group `agent_config` — FIM directories, registry keys, ignore list, Sysmon + WMI-Activity eventchannel collection |
| 3 | [`ignore-rules-windows.md`](ignore-rules-windows.md) | Windows FIM/process noise-suppression rules (100600–100612, 100620–100621) |
| 4 | [`linux-agent-group.md`](linux-agent-group.md) | Linux agent group `agent_config` — FIM on `/etc/shadow`, cron, SSH keys, binaries, ignore list |
| 5 | [`linux-ignore.md`](linux-ignore.md) | Linux FIM/audit noise-suppression rules (100611–100625) |
| 6 | [`sysmon.md`](sysmon.md) | Sysmon install note + Wazuh rules that raise Sysmon events 1–15/22 to level 5 (101100–101115) |
| 7 | [`linux-endpoints-auditd.md`](linux-endpoints-auditd.md) | Full auditd setup on Linux endpoints — install, `auditd.conf`, `af_unix` plugin, `command-monitor.rules`, load rules, Wazuh `<localfile>`, test |
| 8 | [`manager-conf-wrapper (1).md`](manager-conf-wrapper%20%281%29.md) | The `custom-opencti` shell wrapper (calls the bundled Wazuh Python against `custom-opencti.py`), ownership/permissions |
| 9 | [`opencti-custom.py`](opencti-custom.py) | The actual `custom-opencti.py` integration script — extracts IOCs (IPv4/IPv6, domains, URLs, hashes) from Sysmon, FIM/syscheck and auditd alerts and queries OpenCTI |
| 10 | [`local-rules.md`](local-rules.md) | `local_rules.xml` — OpenCTI base rules (100210–100216), Linux auditd targeted-binary rules (100499–100510), high-score escalation (100221–100222) |
| 11 | [`ossec-conf.md`](ossec-conf.md) | The `<integration>` block for `ossec.conf` — group list, `api_key`, `hook_url` (two variants shown) |

## What's still missing from this repo

Going through the Notion page phase by phase, these pieces are referenced but **not yet a file
in this repo** — say if you want them added the same way:

## Known issues carried over from the Notion notes (not changed here — flagging only)

- **Duplicate rule IDs**: 100611, 100612 and 100621 are defined in both
  `ignore-rules-windows.md` and `linux-ignore.md` with different `<field>` matches. Loading both
  files on the same Wazuh manager will make `wazuh-analysisd -t` fail on duplicate IDs — one side
  needs renumbering before deployment.
- **`opencti-custom.py`** expects the wrapper script from step 8 to be saved as
  `/var/ossec/integrations/custom-opencti` (no extension) and the script itself as
  `/var/ossec/integrations/custom-opencti.py`, both owned `root:wazuh`, mode `750`.
- **`ossec-conf.md`** contains a live-looking OpenCTI API token in plain text
  (`flgrn_octi_tkn_...`) — rotate it in OpenCTI before publishing/sharing this repo.
- **`af_unix.conf`** in `linux-endpoints-auditd.md` (Step 4) — path differs between distros
  (`/etc/audisp/plugins.d/` vs `/etc/audit/plugins.d/`); check which exists on your endpoint
  before editing.

## Order of operations (quick view)

```
1. Install OpenCTI (Docker)
        │
2. Wire OpenCTI ⇄ Wazuh Indexer (not yet in repo — see above)
        │
3. Wazuh Manager: agent groups (windows/linux), ignore rules, sysmon rules
        │
4. Windows endpoints: install Sysmon, apply agent group
   Linux endpoints:   install/configure auditd, apply agent group
        │
5. Wazuh Manager: custom-opencti wrapper + script, local_rules.xml, ossec.conf integration block
        │
6. Restart wazuh-manager / wazuh-dashboard / wazuh-indexer, test end-to-end
```
