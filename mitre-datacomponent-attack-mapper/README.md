# mitre-datacomponent-attack-mapper

Fetches ATT&CK data from the [MITRE TAXII API](https://attack-taxii.mitre.org) and maps Data Components to ATT&CK Techniques via Analytics and Detection Strategies.

Useful for understanding which data sources (e.g. Process Creation, Network Traffic) cover the most ATT&CK techniques — and conversely, which techniques have the broadest data source coverage.

Supports Enterprise, Mobile, and ICS ATT&CK matrices.

## Requirements

```bash
pip install requests
```

## Usage

**Fetch Enterprise ATT&CK and generate a report (default):**
```bash
python mitre-datacomponent-attack-mapper.py
```

**Use a different matrix:**
```bash
python mitre-datacomponent-attack-mapper.py --matrix ics
```

**Force re-fetch (ignore cache):**
```bash
python mitre-datacomponent-attack-mapper.py --no-cache
```

## Options

| Flag | Description |
|------|-------------|
| `--matrix` | ATT&CK matrix: `enterprise`, `mobile`, `ics` (default: `enterprise`) |
| `--cache-file PATH` | Path for the raw TAXII cache (default: `mitre-attack-cache.json`) |
| `--no-cache` | Force re-fetch from TAXII even if a cache exists |
| `--top N` | Number of top entries to show (default: 20) |
| `--sections LIST...` | Output sections: `summary datacomponents techniques mappings errors` |
| `--json-out FILE` | Write full analysis to a JSON file |

## How it works

The resolution chain traverses four object types:
1. `x-mitre-analytic` lists the Data Components it covers (via `x_mitre_log_source_references[].x_mitre_data_component_ref`)
2. `x-mitre-analytic` links to its Detection Strategy (via a `DET####/AN####` URL in `external_references`)
3. `x-mitre-detection-strategy` links to an ATT&CK Technique (via a STIX `detects` relationship)

Resolved direction: `Data Component <- Analytic -> Detection Strategy -> Technique`

## Example

```bash
python mitre-datacomponent-attack-mapper.py --top 30
```

```
Fetching Enterprise ATT&CK from TAXII...
  Fetched 24771 objects in 5 page(s).
MITRE ATT&CK Data Component / Technique Mapping Report
=======================================================
Matrix                         : enterprise
Cache file                     : mitre-attack-cache.json
Total objects fetched          : 24771
Unique data components         : 109
Unique analytics               : 1739
Unique detection strategies    : 691
Techniques in collection       : 691
Data components with mappings  : 97
Techniques mapped              : 650
Unique DC-technique pairs      : 2615
Resolve errors                 : 0
Fetch errors                   : 0

Top 30 Data Components by Unique Technique Count
------------------------------------------------
  1.  Process Creation                      452
  2.  Command Execution                     209
  3.  File Creation                         174
  4.  Network Connection Creation           151
  5.  Network Traffic Content               139
  6.  File Modification                     115
  7.  Module Load                           109
  8.  Application Log Content                98
  9.  Network Traffic Flow                   92
 10.  File Access                            91
 11.  Windows Registry Key Modification      86
 12.  Process Access                         77
 13.  File Metadata                          64
 14.  Logon Session Creation                 56
 15.  OS API Execution                       54
 16.  User Account Authentication            53
 17.  Logon Session Metadata                 30
 18.  Process Metadata                       30
 19.  Script Execution                       28
 20.  Service Creation                       28
 21.  Response Content                       28
 22.  Process Modification                   24
 23.  User Account Modification              21
 24.  User Account Metadata                  20
 25.  Cloud Service Modification             18
 26.  Active Directory Object Modification   17
 27.  Scheduled Job Creation                 15
 28.  Driver Load                            14
 29.  Host Status                            14
 30.  Service Metadata                       13

Top 30 ATT&CK Techniques by Data Component Coverage
---------------------------------------------------
  1.  T1204: User Execution                                  11
  2.  T1124: System Time Discovery                           11
  3.  T1562: Impair Defenses                                 11
  4.  T1480: Execution Guardrails                            11
  5.  T1546: Event Triggered Execution                       10
  6.  T1036.005: Match Legitimate Resource Name or Location  10
  7.  T1125: Video Capture                                    9
  8.  T1048: Exfiltration Over Alternative Protocol           9
  9.  T1578: Modify Cloud Compute Infrastructure              9
 10.  T1189: Drive-by Compromise                              9
 11.  T1056.001: Keylogging                                   9
 12.  T1552: Unsecured Credentials                            9
 13.  T1213.006: Databases                                    8
 14.  T1567: Exfiltration Over Web Service                    8
 15.  T1056: Input Capture                                    8
 16.  T1204.003: Malicious Image                              8
 17.  T1496.001: Compute Hijacking                            8
 18.  T1195.002: Compromise Software Supply Chain             8
 19.  T1213: Data from Information Repositories               8
 20.  T1127.001: MSBuild                                      8
 21.  T1200: Hardware Additions                               8
 22.  T1480.001: Environmental Keying                         8
 23.  T1496: Resource Hijacking                               8
 24.  T1037: Boot or Logon Initialization Scripts             8
 25.  T1218.014: MMC                                          8
 26.  T1036: Masquerading                                     8
 27.  T1210: Exploitation of Remote Services                  7
 28.  T1491.001: Internal Defacement                          7
 29.  T1129: Shared Modules                                   7
 30.  T1218.009: Regsvcs/Regasm                               7

Top 30 ATT&CK Techniques by Data Component Coverage (detail)
------------------------------------------------------------
  1.  T1124: System Time Discovery                           11 distinct data component(s)
  2.  T1204: User Execution                                  11 distinct data component(s)
  3.  T1480: Execution Guardrails                            11 distinct data component(s)
  4.  T1562: Impair Defenses                                 11 distinct data component(s)
  5.  T1036.005: Match Legitimate Resource Name or Location  10 distinct data component(s)
  6.  T1546: Event Triggered Execution                       10 distinct data component(s)
  7.  T1048: Exfiltration Over Alternative Protocol           9 distinct data component(s)
  8.  T1056.001: Keylogging                                   9 distinct data component(s)
  9.  T1125: Video Capture                                    9 distinct data component(s)
 10.  T1189: Drive-by Compromise                              9 distinct data component(s)
 11.  T1552: Unsecured Credentials                            9 distinct data component(s)
 12.  T1578: Modify Cloud Compute Infrastructure              9 distinct data component(s)
 13.  T1036: Masquerading                                     8 distinct data component(s)
 14.  T1037: Boot or Logon Initialization Scripts             8 distinct data component(s)
 15.  T1056: Input Capture                                    8 distinct data component(s)
 16.  T1127.001: MSBuild                                      8 distinct data component(s)
 17.  T1195.002: Compromise Software Supply Chain             8 distinct data component(s)
 18.  T1200: Hardware Additions                               8 distinct data component(s)
 19.  T1204.003: Malicious Image                              8 distinct data component(s)
 20.  T1213.006: Databases                                    8 distinct data component(s)
 21.  T1213: Data from Information Repositories               8 distinct data component(s)
 22.  T1218.014: MMC                                          8 distinct data component(s)
 23.  T1480.001: Environmental Keying                         8 distinct data component(s)
 24.  T1496.001: Compute Hijacking                            8 distinct data component(s)
 25.  T1496: Resource Hijacking                               8 distinct data component(s)
 26.  T1567: Exfiltration Over Web Service                    8 distinct data component(s)
 27.  T1011: Exfiltration Over Other Network Medium           7 distinct data component(s)
 28.  T1027.014: Polymorphic Code                             7 distinct data component(s)
 29.  T1027: Obfuscated Files or Information                  7 distinct data component(s)
 30.  T1055: Process Injection                                7 distinct data component(s)

Top 30 Data Components by Technique Coverage (detail)
-----------------------------------------------------
  1.  Process Creation                      452 distinct technique(s)
  2.  Command Execution                     209 distinct technique(s)
  3.  File Creation                         174 distinct technique(s)
  4.  Network Connection Creation           151 distinct technique(s)
  5.  Network Traffic Content               139 distinct technique(s)
  6.  File Modification                     115 distinct technique(s)
  7.  Module Load                           109 distinct technique(s)
  8.  Application Log Content                98 distinct technique(s)
  9.  Network Traffic Flow                   92 distinct technique(s)
 10.  File Access                            91 distinct technique(s)
 11.  Windows Registry Key Modification      86 distinct technique(s)
 12.  Process Access                         77 distinct technique(s)
 13.  File Metadata                          64 distinct technique(s)
 14.  Logon Session Creation                 56 distinct technique(s)
 15.  OS API Execution                       54 distinct technique(s)
 16.  User Account Authentication            53 distinct technique(s)
 17.  Logon Session Metadata                 30 distinct technique(s)
 18.  Process Metadata                       30 distinct technique(s)
 19.  Response Content                       28 distinct technique(s)
 20.  Script Execution                       28 distinct technique(s)
 21.  Service Creation                       28 distinct technique(s)
 22.  Process Modification                   24 distinct technique(s)
 23.  User Account Modification              21 distinct technique(s)
 24.  User Account Metadata                  20 distinct technique(s)
 25.  Cloud Service Modification             18 distinct technique(s)
 26.  Active Directory Object Modification   17 distinct technique(s)
 27.  Scheduled Job Creation                 15 distinct technique(s)
 28.  Driver Load                            14 distinct technique(s)
 29.  Host Status                            14 distinct technique(s)
 30.  Service Metadata                       13 distinct technique(s)
```
