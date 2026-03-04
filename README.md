# ClawGuard Shield Scan Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-ClawGuard%20Shield%20Scan-blue?logo=github)](https://github.com/marketplace/actions/clawguard-shield-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Scan your codebase for prompt injection vulnerabilities in CI/CD.**

This GitHub Action uses the [ClawGuard Shield API](https://prompttools.co/shield) to detect prompt injections, data exfiltration attempts, jailbreaks, and social engineering in your code — especially in prompt templates and LLM-facing files.

## Quick Start

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  clawguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: joergmichno/clawguard-scan-action@v1
        with:
          api-key: ${{ secrets.CLAWGUARD_API_KEY }}
```

That's it. The action will:
1. Find files matching common patterns (`.py`, `.js`, `.ts`, `.yml`, `.md`)
2. Detect which files contain prompt-like content
3. Scan them via the Shield API
4. Fail the check if HIGH or CRITICAL findings are detected
5. Post a summary to the PR

## Get Your API Key

1. Go to [prompttools.co/shield](https://prompttools.co/shield)
2. Register for a free API key (100 scans/day)
3. Add it as a GitHub secret: `Settings > Secrets > CLAWGUARD_API_KEY`

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `api-key` | (required) | Your ClawGuard Shield API key |
| `paths` | `**/*.py` `**/*.js` `**/*.ts` `**/*.yml` `**/*.yaml` `**/*.md` | Glob patterns for files to scan |
| `fail-on` | `HIGH` | Minimum severity to fail: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE` |
| `scan-mode` | `prompts` | `prompts` = only files with prompt content, `all` = everything |
| `max-file-size` | `50000` | Skip files larger than this (bytes) |
| `api-url` | `https://prompttools.co/api/v1` | Shield API URL (for self-hosted) |

## Outputs

| Output | Description |
|--------|-------------|
| `total-files` | Number of files scanned |
| `total-findings` | Total security findings |
| `max-severity` | Highest severity found |
| `report` | Path to JSON report file |

## Examples

### Scan Only Python Files

```yaml
- uses: joergmichno/clawguard-scan-action@v1
  with:
    api-key: ${{ secrets.CLAWGUARD_API_KEY }}
    paths: |
      **/*.py
      prompts/**/*.txt
```

### Fail Only on Critical

```yaml
- uses: joergmichno/clawguard-scan-action@v1
  with:
    api-key: ${{ secrets.CLAWGUARD_API_KEY }}
    fail-on: CRITICAL
```

### Scan All Files (Not Just Prompts)

```yaml
- uses: joergmichno/clawguard-scan-action@v1
  with:
    api-key: ${{ secrets.CLAWGUARD_API_KEY }}
    scan-mode: all
```

### Use Scan Results in Next Steps

```yaml
- uses: joergmichno/clawguard-scan-action@v1
  id: scan
  with:
    api-key: ${{ secrets.CLAWGUARD_API_KEY }}
    fail-on: NONE  # Don't fail, just report

- name: Check results
  run: |
    echo "Files scanned: ${{ steps.scan.outputs.total-files }}"
    echo "Findings: ${{ steps.scan.outputs.total-findings }}"
    echo "Max severity: ${{ steps.scan.outputs.max-severity }}"
```

### Self-Hosted Shield

```yaml
- uses: joergmichno/clawguard-scan-action@v1
  with:
    api-key: ${{ secrets.CLAWGUARD_API_KEY }}
    api-url: https://your-shield-instance.com/api/v1
```

## What It Detects

ClawGuard Shield scans for 42+ threat patterns:

| Category | Examples |
|----------|---------|
| **Prompt Injection** | Instruction overrides, context manipulation, delimiter injection |
| **Jailbreaks** | DAN attacks, roleplay exploits, hypothetical abuse |
| **Data Exfiltration** | URL injection, email harvesting, system info extraction |
| **Social Engineering** | Authority impersonation, urgency manipulation |
| **Encoding Tricks** | Base64, hex, ROT13 encoded payloads |

## PR Summary

The action writes a formatted summary to your PR check:

| Metric | Value |
|--------|-------|
| Files scanned | 12 |
| Total findings | 3 |
| Max severity | HIGH |
| Fail threshold | HIGH |

### Findings

| File | Severity | Risk | Findings |
|------|----------|------|----------|
| `prompts/system.py` | HIGH | 7/10 | 2 |
| `config/templates.yml` | MEDIUM | 4/10 | 1 |

## Related

- [ClawGuard](https://github.com/joergmichno/clawguard) — Open-source security scanner (zero dependencies)
- [ClawGuard Shield API](https://github.com/joergmichno/clawguard-shield) — The API behind this action
- [Python SDK](https://github.com/joergmichno/clawguard-shield-python) — `pip install clawguard-shield`
- [Prompt Lab](https://prompttools.co) — Interactive prompt injection playground

## License

MIT
