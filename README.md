# Security Telemetry Utilities

A little collection of tools I yelled at my robot to make. Each maps ATT&CK data from a different angle.

## Tools

### [sigma-logsource-attack-mapper](sigma-logsource-attack-mapper/)

Parses [Sigma](https://github.com/SigmaHQ/sigma) rule YAML files and aggregates logsource usage, tag usage, and ATT&CK technique coverage. This is useful for identifying trends and inferring (but not necessarily specifically deducing) value in things like specific log sources. 

```bash
pip install pyyaml
python sigma-logsource-attack-mapper/sigma-logsource-attack-mapper.py --sigma-repo /path/to/sigma
```

### [mitre-datacomponent-attack-mapper](mitre-datacomponent-attack-mapper/)

Fetches ATT&CK data directly from the MITRE TAXII API and maps Data Components to ATT&CK Techniques. This has a similar use case: identifying what data components map to the most MITRE ATT&CK techniques, such that we may best infer (though not necessarily deduce) what may be the best log sources. 

```bash
pip install requests
python mitre-datacomponent-attack-mapper/mitre-datacomponent-attack-mapper.py
```
