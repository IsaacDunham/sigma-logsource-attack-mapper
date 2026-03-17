# sigma-logsource-attack-mapper

This is a little project I yelled at my robot to make. It's designed to parse [Sigma](https://github.com/SigmaHQ/sigma) rule YAML files and produces aggregate analytics for logsource usage, tag usage, MITRE ATT&CK technique coverage, and technique to logsource mappings.

With this, you can get a better understanding of what TTPs and data sources are occurring most frequently in a detection rule set. From that, you might infer (though not deduce) log source value, prevalence of a TTP, etc. 

It works natively with the [official SigmaHQ/sigma repo](https://github.com/SigmaHQ/sigma) via `--sigma-repo`, or against any directory of YAML rule files.

## Requirements

``` bash
pip install pyyaml
```

## Usage

**Scan the current directory** (no arguments — recursively searches cwd for `.yml` files):
``` bash
python sigma-logsource-attack-mapper.py
```

**Point to the official SigmaHQ/sigma repo**:
``` bash
python sigma-logsource-attack-mapper.py --sigma-repo /path/to/sigma
```

**Scan specific directories:**
```
python sigma-logsource-attack-mapper.py --paths rules/ rules-threat-hunting/
```

## Options

| Flag | Description |
|------|-------------|
| `--sigma-repo PATH` | Path to the official SigmaHQ/sigma repo root |
| `--paths PATH...` | One or more rule directories to scan recursively |
| `--include-deprecated` | Include `deprecated/` folder |
| `--include-unsupported` | Include `unsupported/` folder |
| `--top N` | Number of top entries to show (default: 20) |
| `--logsource-views VIEW...` | Aggregation dimensions: `product`, `category`, `service`, or combos like `product+category` (default: `product+category+service`) |
| `--require-logsource` | Skip rules with no logsource fields |
| `--require-techniques` | Skip rules with no ATT&CK technique tags |
| `--status-filter LIST` | Comma-separated statuses to include (e.g. `stable,test`) |
| `--attack-filter LIST` | Comma-separated tactics/techniques to include (e.g. `execution,t1190`) |
| `--exclude-path-regex REGEX` | Exclude rule files matching this path regex |
| `--sections LIST...` | Output sections: `summary logsources tags techniques mappings errors` |
| `--json-out FILE` | Write full analysis to a JSON file |

## Example

``` bash
python sigma-logsource-attack-mapper.py --sigma-repo "H:\GitHub\sigma" --require-techniques --status-filter stable --logsource-views product+category product+service --top 30
```

``` title:Output
Sigma Logsource / ATT&CK Mapping Report
=======================================
Files scanned      : 3468
Rules processed    : 101
Rules skipped      : 3367
Unique tags        : 97
Unique techniques  : 67
Parse errors       : 0
Paths scanned      : H:\GitHub\sigma\rules, H:\GitHub\sigma\rules-compliance, H:\GitHub\sigma\rules-dfir, H:\GitHub\sigma\rules-emerging-threats, H:\GitHub\sigma\rules-placeholder, H:\GitHub\sigma\rules-threat-hunting
Views              : product+category, product+service
Active filters     : require_techniques=True, status_filter=['stable']
Skip reasons       : status_filtered_out=2890, missing_technique_tags=477

Top 30 Logsources by Rule Count (product+category)
--------------------------------------------------
  1.  product=windows | category=process_creation      38
  2.  product=windows | category=-                     24
  3.  product=linux | category=-                        6
  4.  product=linux | category=process_creation         6
  5.  product=- | category=antivirus                    4
  6.  product=windows | category=process_access         3
  7.  product=aws | category=-                          2
  8.  product=- | category=proxy                        2
  9.  product=django | category=application             1
 10.  product=python | category=application             1
 11.  product=ruby_on_rails | category=application      1
 12.  product=spring | category=application             1
 13.  product=linux | category=file_event               1
 14.  product=linux | category=network_connection       1
 15.  product=- | category=dns                          1
 16.  product=zeek | category=-                         1
 17.  product=windows | category=create_remote_thread   1
 18.  product=windows | category=image_load             1
 19.  product=windows | category=network_connection     1
 20.  product=windows | category=ps_classic_start       1
 21.  product=windows | category=registry_event         1
 22.  product=windows | category=registry_set           1
 23.  product=windows | category=file_event             1
 24.  product=- | category=webserver                    1

Top 30 Logsources by Rule Count (product+service)
-------------------------------------------------
  1.  product=windows | service=-          48
  2.  product=windows | service=windefend  11
  3.  product=linux | service=-            10
  4.  product=windows | service=security   10
  5.  product=- | service=-                 8
  6.  product=linux | service=auditd        3
  7.  product=windows | service=system      3
  8.  product=aws | service=cloudtrail      2
  9.  product=django | service=-            1
 10.  product=python | service=-            1
 11.  product=ruby_on_rails | service=-     1
 12.  product=spring | service=-            1
 13.  product=linux | service=clamav        1
 14.  product=zeek | service=http           1

Top 30 Tags
-----------
  1.  attack.defense-evasion       34
  2.  attack.execution             25
  3.  detection.emerging-threats   19
  4.  attack.impact                13
  5.  attack.privilege-escalation  12
  6.  attack.t1562.001             10
  7.  attack.initial-access         9
  8.  attack.credential-access      9
  9.  attack.persistence            9
 10.  attack.lateral-movement       7
 11.  attack.t1190                  6
 12.  attack.discovery              6
 13.  attack.t1098                  6
 14.  attack.t1059.001              6
 15.  attack.t1003.001              5
 16.  attack.t1047                  5
 17.  car.2019-04-001               5
 18.  attack.t1203                  4
 19.  attack.command-and-control    4
 20.  attack.t1496                  4
 21.  attack.t1490                  4
 22.  attack.t1218.003              4
 23.  attack.g0069                  4
 24.  attack.t1218.011              4
 25.  attack.t1068                  3
 26.  attack.t1548.002              3
 27.  attack.t1566.001              3
 28.  attack.t1204                  2
 29.  attack.t1003                  2
 30.  attack.t1003.002              2

Top 30 ATT&CK Techniques
------------------------
  1.  attack.t1562.001  10
  2.  attack.t1190       6
  3.  attack.t1098       6
  4.  attack.t1059.001   6
  5.  attack.t1003.001   5
  6.  attack.t1047       5
  7.  attack.t1203       4
  8.  attack.t1496       4
  9.  attack.t1490       4
 10.  attack.t1218.003   4
 11.  attack.t1218.011   4
 12.  attack.t1068       3
 13.  attack.t1548.002   3
 14.  attack.t1566.001   3
 15.  attack.t1204       2
 16.  attack.t1003       2
 17.  attack.t1003.002   2
 18.  attack.t1486       2
 19.  attack.t1485       2
 20.  attack.t1082       2
 21.  attack.t1548       2
 22.  attack.t1210       2
 23.  attack.t1021.006   2
 24.  attack.t1059       2
 25.  attack.t1574.002   2
 26.  attack.t1003.003   2
 27.  attack.t1070       2
 28.  attack.t1204.002   2
 29.  attack.t1055       2
 30.  attack.t1071.001   2

Top 30 ATT&CK Techniques by Logsource Coverage (product+category)
-----------------------------------------------------------------
  1.  attack.t1190      6 distinct logsource(s)
  2.  attack.t1003.001  4 distinct logsource(s)
  3.  attack.t1496      4 distinct logsource(s)
  4.  attack.t1068      3 distinct logsource(s)
  5.  attack.t1203      3 distinct logsource(s)
  6.  attack.t1218.003  3 distinct logsource(s)
  7.  attack.t1003      2 distinct logsource(s)
  8.  attack.t1003.002  2 distinct logsource(s)
  9.  attack.t1021.006  2 distinct logsource(s)
 10.  attack.t1047      2 distinct logsource(s)
 11.  attack.t1055      2 distinct logsource(s)
 12.  attack.t1059.001  2 distinct logsource(s)
 13.  attack.t1082      2 distinct logsource(s)
 14.  attack.t1204      2 distinct logsource(s)
 15.  attack.t1204.002  2 distinct logsource(s)
 16.  attack.t1210      2 distinct logsource(s)
 17.  attack.t1218.011  2 distinct logsource(s)
 18.  attack.t1485      2 distinct logsource(s)
 19.  attack.t1486      2 distinct logsource(s)
 20.  attack.t1490      2 distinct logsource(s)
 21.  attack.t1548      2 distinct logsource(s)
 22.  attack.t1548.002  2 distinct logsource(s)
 23.  attack.t1566.001  2 distinct logsource(s)
 24.  attack.t1574.002  2 distinct logsource(s)
 25.  attack.t1003.003  1 distinct logsource(s)
 26.  attack.t1018      1 distinct logsource(s)
 27.  attack.t1021.003  1 distinct logsource(s)
 28.  attack.t1027      1 distinct logsource(s)
 29.  attack.t1027.001  1 distinct logsource(s)
 30.  attack.t1033      1 distinct logsource(s)

Top 30 Logsources by Technique Coverage (product+category)
----------------------------------------------------------
  1.  product=windows | category=process_creation      40 distinct technique(s)
  2.  product=windows | category=-                     10 distinct technique(s)
  3.  product=- | category=antivirus                    8 distinct technique(s)
  4.  product=linux | category=-                        6 distinct technique(s)
  5.  product=linux | category=process_creation         6 distinct technique(s)
  6.  product=windows | category=process_access         5 distinct technique(s)
  7.  product=zeek | category=-                         5 distinct technique(s)
  8.  product=- | category=proxy                        3 distinct technique(s)
  9.  product=aws | category=-                          3 distinct technique(s)
 10.  product=- | category=dns                          2 distinct technique(s)
 11.  product=- | category=webserver                    1 distinct technique(s)
 12.  product=django | category=application             1 distinct technique(s)
 13.  product=linux | category=file_event               1 distinct technique(s)
 14.  product=linux | category=network_connection       1 distinct technique(s)
 15.  product=python | category=application             1 distinct technique(s)
 16.  product=ruby_on_rails | category=application      1 distinct technique(s)
 17.  product=spring | category=application             1 distinct technique(s)
 18.  product=windows | category=create_remote_thread   1 distinct technique(s)
 19.  product=windows | category=file_event             1 distinct technique(s)
 20.  product=windows | category=image_load             1 distinct technique(s)
 21.  product=windows | category=network_connection     1 distinct technique(s)
 22.  product=windows | category=ps_classic_start       1 distinct technique(s)
 23.  product=windows | category=registry_event         1 distinct technique(s)
 24.  product=windows | category=registry_set           1 distinct technique(s)

Top 30 ATT&CK Techniques by Logsource Coverage (product+service)
----------------------------------------------------------------
  1.  attack.t1190      6 distinct logsource(s)
  2.  attack.t1068      3 distinct logsource(s)
  3.  attack.t1203      3 distinct logsource(s)
  4.  attack.t1496      3 distinct logsource(s)
  5.  attack.t1003      2 distinct logsource(s)
  6.  attack.t1003.001  2 distinct logsource(s)
  7.  attack.t1003.002  2 distinct logsource(s)
  8.  attack.t1021.006  2 distinct logsource(s)
  9.  attack.t1047      2 distinct logsource(s)
 10.  attack.t1055      2 distinct logsource(s)
 11.  attack.t1082      2 distinct logsource(s)
 12.  attack.t1204      2 distinct logsource(s)
 13.  attack.t1204.002  2 distinct logsource(s)
 14.  attack.t1210      2 distinct logsource(s)
 15.  attack.t1485      2 distinct logsource(s)
 16.  attack.t1486      2 distinct logsource(s)
 17.  attack.t1562.001  2 distinct logsource(s)
 18.  attack.t1566.001  2 distinct logsource(s)
 19.  attack.t1003.003  1 distinct logsource(s)
 20.  attack.t1018      1 distinct logsource(s)
 21.  attack.t1021.003  1 distinct logsource(s)
 22.  attack.t1027      1 distinct logsource(s)
 23.  attack.t1027.001  1 distinct logsource(s)
 24.  attack.t1033      1 distinct logsource(s)
 25.  attack.t1036      1 distinct logsource(s)
 26.  attack.t1036.005  1 distinct logsource(s)
 27.  attack.t1053      1 distinct logsource(s)
 28.  attack.t1053.002  1 distinct logsource(s)
 29.  attack.t1057      1 distinct logsource(s)
 30.  attack.t1059      1 distinct logsource(s)

Top 30 Logsources by Technique Coverage (product+service)
---------------------------------------------------------
  1.  product=windows | service=-          42 distinct technique(s)
  2.  product=- | service=-                14 distinct technique(s)
  3.  product=linux | service=-             9 distinct technique(s)
  4.  product=windows | service=security    6 distinct technique(s)
  5.  product=zeek | service=http           5 distinct technique(s)
  6.  product=aws | service=cloudtrail      3 distinct technique(s)
  7.  product=linux | service=auditd        3 distinct technique(s)
  8.  product=windows | service=system      3 distinct technique(s)
  9.  product=windows | service=windefend   2 distinct technique(s)
 10.  product=django | service=-            1 distinct technique(s)
 11.  product=linux | service=clamav        1 distinct technique(s)
 12.  product=python | service=-            1 distinct technique(s)
 13.  product=ruby_on_rails | service=-     1 distinct technique(s)
 14.  product=spring | service=-            1 distinct technique(s)
```