# ZDFinder

Automated security vulnerability analysis for source code repositories using Ollama and large language models.

## Overview

ZDFinder (ZeroDay Finder) analyzes source code repositories to identify potential security vulnerabilities. It leverages local LLMs via Ollama to perform comprehensive security audits, generating detailed reports with findings, severity ratings, and proof-of-concept scripts for each discovered vulnerability.

## Features

- **Comprehensive Security Analysis**: Detects OWASP Top 10, CWE Top 25, and common vulnerability patterns
- **Automated Proof-of-Concept Generation**: Creates executable PoC scripts for each finding
- **Chunked Processing**: Handles large codebases by intelligently chunking analysis
- **Detailed Reporting**: Generates markdown reports with severity classifications and remediation guidance
- **Flexible Configuration**: Customizable Ollama endpoint, model selection, and output paths
- **Model Preloading**: Warm-up capability for faster subsequent analyses

## Requirements

- Python 3.8+
- Ollama running with a supported model
- Network access to the Ollama instance

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install requests
   ```
3. Ensure Ollama is running and accessible

## Configuration

Edit `security_analyzer.py` to customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://192.168.1.151:11434` | Ollama API endpoint |
| `MODEL_NAME` | `huihui_ai/qwen3-coder-abliterated:30b` | Model to use for analysis |
| `REQUEST_TIMEOUT` | `600` | API request timeout (seconds) |
| `MAX_CHUNK_SIZE` | `100000` | Max characters per analysis chunk |

## Usage

### Basic Analysis

```bash
python3 security_analyzer.py /path/to/repository
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Custom output file path |
| `--ollama-url` | Ollama server URL (default: configured value) |
| `-w, --warmup` | Warm up model before analysis |
| `--preload-only` | Load model into memory and exit |
| `--skip-pull` | Skip pulling model if not available |

### Example Commands

```bash
# Analyze a repository
python3 security_analyzer.py /home/user/myproject

# Use custom Ollama server
python3 security_analyzer.py /home/user/myproject --ollama-url http://localhost:11434

# Preload model (run before main analysis for faster results)
python3 security_analyzer.py /path/to/repo --preload-only

# Custom output location
python3 security_analyzer.py /home/user/myproject -o /tmp/report.md
```

## Output

After analysis, ZDFinder creates:

```
security_reports/
└── MMDYY-repo_name/
    ├── security_report.md      # Full analysis report
    └── security_pocs/         # Proof-of-concept scripts
        ├── poc_CWE-XXX_file.py
        └── ...
```

### Report Contents

- **Summary**: Total vulnerabilities by severity (Critical, High, Medium, Low)
- **Vulnerability Details**: Each finding includes:
  - CWE classification
  - Severity rating
  - File and line number
  - Description and impact
  - Proof of concept
  - Testing instructions

## Supported Vulnerability Types

- Injection attacks (SQL, Command, LDAP, XML)
- Authentication and authorization flaws
- Cross-site scripting (XSS)
- Path traversal
- Insecure deserialization
- Hardcoded credentials
- Cryptographic weaknesses
- Race conditions
- Memory safety issues
- Information disclosure
- And more (OWASP/CWE coverage)

## Model Recommendations

This tool works best with coding-focused LLMs. Recommended models:

- `huihui_ai/qwen3-coder-abliterated:30b` (default)
- `qwen2.5-coder:32b`
- `deepseek-coder-v2:236b`
- `codellama:34b`

## Security Considerations

- Runs entirely locally via Ollama
- No code is sent to external services
- Analysis results stored locally
- Review all findings before remediation

## License

MIT License

## Author

RK Davies experimenting with AI evaluation of provided data
