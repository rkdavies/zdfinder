#!/usr/bin/env python3
import os
import sys
import json
import argparse
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

OLLAMA_BASE_URL = "http://192.168.1.151:11434"
MODEL_NAME = "huihui_ai/qwen3-coder-abliterated:30b"
REQUEST_TIMEOUT = 600
config = {"ollama_url": OLLAMA_BASE_URL}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "dist",
    "build",
    ".pytest_cache",
    "vendor",
    "target",
    ".idea",
    ".vscode",
}
SKIP_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".jpg",
    ".png",
    ".gif",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
}

SECURITY_SYSTEM_PROMPT = """You are an expert security researcher specializing in code vulnerability analysis. Your task is to analyze the provided source code for potential security vulnerabilities.

For each file analyzed, identify and document any security issues found. Use the CWE (Common Weakness Enumeration) classification system.

Focus on:
- OWASP Top 10 vulnerabilities
- CWE Top 25 most dangerous software weaknesses
- Input validation issues
- Authentication/authorization flaws
- Command injection
- SQL injection
- XSS vulnerabilities
- Path traversal
- Insecure deserialization
- Hardcoded credentials
- Crypto weaknesses
- Race conditions
- Memory safety issues (buffer overflows, etc.)
- Information disclosure

For each vulnerability found, provide:
1. CWE ID and name
2. Severity (Critical, High, Medium, Low)
3. Description of the vulnerability
4. Location (file and line number)
5. Evidence from the code
6. Potential impact
7. Proof of Concept: A concrete example showing how to exploit this vulnerability
8. How to test for this vulnerability

If no vulnerabilities are found, state that clearly.

Respond in JSON format:
{
  "vulnerabilities": [
    {
      "cwe_id": "CWE-XXX",
      "name": "Vulnerability Name",
      "severity": "Critical|High|Medium|Low",
      "file": "path/to/file",
      "line": line_number,
      "description": "...",
      "evidence": "...",
      "impact": "...",
      "proof_of_concept": "...",
      "how_to_test": "..."
    }
  ],
  "summary": "..."
}"""

REQUEST_TIMEOUT = 300


def get_source_files(repo_path: str) -> List[Dict[str, Any]]:
    files = []
    repo_path_obj = Path(repo_path)

    if not repo_path_obj.exists():
        print(f"Error: Path {repo_path} does not exist")
        sys.exit(1)

    if not repo_path_obj.is_dir():
        print(f"Error: {repo_path} is not a directory")
        sys.exit(1)

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in filenames:
            file_path = Path(root) / filename

            if file_path.suffix in SKIP_EXTENSIONS:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                relative_path = file_path.relative_to(repo_path_obj)
                files.append(
                    {
                        "path": str(relative_path),
                        "absolute_path": str(file_path),
                        "content": content,
                    }
                )
            except Exception as e:
                print(f"Warning: Could not read {file_path}: {e}")

    return files


def check_ollama_available() -> bool:
    try:
        response = requests.get(f"{config['ollama_url']}/api/tags", timeout=10)
        return response.status_code == 200
    except Exception:
        return False


def pull_model() -> bool:
    print(f"Pulling model {MODEL_NAME}...")
    try:
        response = requests.post(
            f"{config['ollama_url']}/api/pull",
            json={"name": MODEL_NAME},
            stream=True,
            timeout=REQUEST_TIMEOUT,
        )
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    if "status" in data:
                        print(f"  {data['status']}")
                except:
                    pass
        return True
    except Exception as e:
        print(f"Error pulling model: {e}")
        return False


def warmup_model() -> bool:
    print(f"Warming up model {MODEL_NAME}...")
    try:
        response = requests.post(
            f"{config['ollama_url']}/api/generate",
            json={
                "model": MODEL_NAME,
                "prompt": "Hello",
                "stream": False,
                "options": {"num_ctx": 32768},
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            print("Model is ready")
            return True
        else:
            print(f"Warmup failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error warming up model: {e}")
        return False


MAX_CHUNK_SIZE = 100000


def analyze_chunk(
    content: str, chunk_num: int, total_chunks: int, repo_name: str
) -> Dict[str, Any]:
    prompt = f"""Analyze the following source code from repository "{repo_name}" for security vulnerabilities.

{SECURITY_SYSTEM_PROMPT}

Here is source code chunk {chunk_num} of {total_chunks}:

{content}

Provide your analysis in JSON format. Include ALL vulnerabilities found in this chunk."""

    try:
        response = requests.post(
            f"{config['ollama_url']}/api/generate",
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_ctx": 32768},
            },
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 200:
            result = response.json()
            try:
                return json.loads(result.get("response", "{}"))
            except json.JSONDecodeError:
                return {
                    "vulnerabilities": [],
                    "summary": f"Failed to parse JSON response from chunk {chunk_num}",
                    "raw_response": result.get("response", "")[:2000],
                }
        else:
            return {
                "vulnerabilities": [],
                "summary": f"Ollama API error: {response.status_code}",
            }
    except Exception as e:
        return {"vulnerabilities": [], "summary": f"Error calling Ollama: {str(e)}"}


def analyze_with_ollama(files: List[Dict[str, Any]], repo_name: str) -> Dict[str, Any]:
    print(f"Analyzing {len(files)} files with {MODEL_NAME}...")

    all_vulnerabilities = []
    chunk_summaries = []

    chunks = []
    current_chunk = []
    current_size = 0

    for f in files:
        file_entry = f"=== File: {f['path']} ===\n{f['content']}\n"
        file_size = len(file_entry)

        if file_size > MAX_CHUNK_SIZE:
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = []
                current_size = 0

            files_in_chunk = []
            chars_in_chunk = 0
            lines = f["content"].split("\n")
            temp_lines = []

            for line in lines:
                test_lines = temp_lines + [line]
                test_content = (
                    f"=== File: {f['path']} ===\n" + "\n".join(test_lines) + "\n"
                )
                if len(test_content) > MAX_CHUNK_SIZE:
                    if temp_lines:
                        files_in_chunk.append(
                            f"=== File: {f['path']} ===\n"
                            + "\n".join(temp_lines)
                            + "\n"
                        )
                        chars_in_chunk += len(files_in_chunk[-1])
                    temp_lines = [line]
                else:
                    temp_lines.append(line)

            if temp_lines:
                files_in_chunk.append(
                    f"=== File: {f['path']} ===\n" + "\n".join(temp_lines) + "\n"
                )

            for fc in files_in_chunk:
                chunks.append(fc)

            continue

        if current_size + file_size > MAX_CHUNK_SIZE:
            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_size = 0

        current_chunk.append(file_entry)
        current_size += file_size

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    if not chunks:
        chunks.append("")

    total_chunks = len(chunks)
    print(f"Split into {total_chunks} chunks (max {MAX_CHUNK_SIZE} chars each)")

    for i, chunk in enumerate(chunks, 1):
        if not chunk.strip():
            continue
        print(f"Analyzing chunk {i}/{total_chunks} ({len(chunk)} chars)...")

        result = analyze_chunk(chunk, i, total_chunks, repo_name)

        vulns = result.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulns)

        if "summary" in result:
            chunk_summaries.append(f"Chunk {i}: {result['summary']}")

        if "raw_response" in result:
            chunk_summaries.append(f"Chunk {i} raw: {result['raw_response'][:500]}")

    seen = set()
    unique_vulns = []
    for vuln in all_vulnerabilities:
        key = (vuln.get("cwe_id"), vuln.get("file"), vuln.get("line"))
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)

    return {
        "vulnerabilities": unique_vulns,
        "summary": f"Analyzed {total_chunks} chunks. Total vulnerabilities found: {len(unique_vulns)}. "
        + " | ".join(chunk_summaries),
    }


def create_poc_script(vuln: Dict[str, Any], repo_path: str) -> Optional[str]:
    poc_dir = Path(repo_path) / "security_pocs"
    poc_dir.mkdir(exist_ok=True)

    safe_name = f"{vuln.get('cwe_id', 'unknown')}_{vuln.get('file', 'unknown').replace('/', '_').replace('\\', '_')}"
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in ("_", "-"))[:100]

    file_path = poc_dir / f"poc_{safe_name}.py"

    poc_content = f'''#!/usr/bin/env python3
"""
Proof of Concept for {vuln.get("cwe_id", "N/A")} - {vuln.get("name", "Unknown Vulnerability")}
Severity: {vuln.get("severity", "Unknown")}
File: {vuln.get("file", "Unknown")}
Line: {vuln.get("line", "Unknown")}

Description:
{vuln.get("description", "No description")}

Evidence:
{vuln.get("evidence", "No evidence")}

Impact:
{vuln.get("impact", "No impact description")}

How to Test:
{vuln.get("how_to_test", "No testing instructions")}
"""

import os
import sys

def main():
    print("=" * 60)
    print(f"PoC: {vuln.get("name", "Unknown")}")
    print(f"CWE: {vuln.get("cwe_id", "N/A")}")
    print("=" * 60)
    
    print("\\nThis is a generated proof of concept.")
    print("Review the vulnerability details above and test manually.")
    print("Some vulnerabilities may require specific conditions to exploit.")

if __name__ == "__main__":
    main()
'''

    try:
        with open(file_path, "w") as f:
            f.write(poc_content)
        os.chmod(file_path, 0o755)
        return str(file_path)
    except Exception as e:
        print(f"Warning: Could not create PoC: {e}")
        return None


def generate_report(
    analysis: Dict[str, Any],
    repo_name: str,
    repo_path: str,
    files: List[Dict[str, Any]],
    report_dir: str = None,
) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        "# Security Analysis Report",
        f"",
        f"**Repository:** {repo_name}",
        f"**Path:** {repo_path}",
        f"**Date:** {timestamp}",
        f"**Model:** {MODEL_NAME}",
        f"**Files Analyzed:** {len(files)}",
        "",
        "---",
        "",
    ]

    vulnerabilities = analysis.get("vulnerabilities", [])

    if vulnerabilities:
        critical = [v for v in vulnerabilities if v.get("severity") == "Critical"]
        high = [v for v in vulnerabilities if v.get("severity") == "High"]
        medium = [v for v in vulnerabilities if v.get("severity") == "Medium"]
        low = [v for v in vulnerabilities if v.get("severity") == "Low"]

        report_lines.extend(
            [
                "## Summary",
                "",
                f"**Total Vulnerabilities Found:** {len(vulnerabilities)}",
                f"- Critical: {len(critical)}",
                f"- High: {len(high)}",
                f"- Medium: {len(medium)}",
                f"- Low: {len(low)}",
                "",
                "---",
                "",
            ]
        )

        severity_order = [
            ("Critical", critical),
            ("High", high),
            ("Medium", medium),
            ("Low", low),
        ]

        for severity, vulns in severity_order:
            if not vulns:
                continue

            report_lines.append(f"## {severity} Severity Vulnerabilities")
            report_lines.append("")

            for i, vuln in enumerate(vulns, 1):
                poc_path = create_poc_script(vuln, report_dir or repo_path)

                report_lines.extend(
                    [
                        f"### {i}. {vuln.get('name', 'Unknown')} ({vuln.get('cwe_id', 'N/A')})",
                        "",
                        f"**File:** {vuln.get('file', 'Unknown')}",
                        f"**Line:** {vuln.get('line', 'Unknown')}",
                        "",
                        "**Description:**",
                        vuln.get("description", "No description"),
                        "",
                        "**Evidence:**",
                        f"```\n{vuln.get('evidence', 'No evidence')}\n```",
                        "",
                        "**Impact:**",
                        vuln.get("impact", "No impact description"),
                        "",
                        "**Proof of Concept:**",
                        vuln.get("proof_of_concept", "No PoC provided"),
                        "",
                        "**How to Test:**",
                        vuln.get("how_to_test", "No testing instructions"),
                        "",
                    ]
                )

                if poc_path:
                    report_lines.append(f"**PoC Script:** `{poc_path}`")

                report_lines.append("---")
                report_lines.append("")
    else:
        report_lines.extend(
            [
                "## Summary",
                "",
                "No vulnerabilities were identified in this analysis.",
                "",
            ]
        )

    if "summary" in analysis:
        report_lines.extend(
            [
                "---",
                "",
                "## Additional Notes",
                "",
                analysis["summary"],
            ]
        )

    if "raw_response" in analysis:
        report_lines.extend(
            [
                "",
                "## Raw Model Response",
                "",
                "```",
                analysis["raw_response"][:2000],
                "```",
            ]
        )

    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a git repository for security vulnerabilities using Ollama"
    )
    parser.add_argument("repo_path", help="Path to the git repository to analyze")
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for the report (default: security_report.md)",
    )
    parser.add_argument(
        "--skip-pull",
        action="store_true",
        help="Skip pulling the model if not available",
    )
    parser.add_argument(
        "--ollama-url",
        default=OLLAMA_BASE_URL,
        help=f"Ollama API URL (default: {OLLAMA_BASE_URL})",
    )
    parser.add_argument(
        "--warmup",
        "-w",
        action="store_true",
        help="Warm up/load the model before analysis",
    )
    parser.add_argument(
        "--preload-only",
        action="store_true",
        help="Only preload the model and exit (useful for priming the cache)",
    )

    args = parser.parse_args()
    config["ollama_url"] = args.ollama_url

    if args.warmup or args.preload_only:
        if not check_ollama_available():
            print(f"Cannot connect to Ollama at {config['ollama_url']}")
            sys.exit(1)
        warmup_model()
        if args.preload_only:
            print("Model preloaded. Exiting.")
            sys.exit(0)

    repo_path = os.path.abspath(args.repo_path)
    repo_name = Path(repo_path).name

    print(f"Repository: {repo_name}")
    print(f"Path: {repo_path}")

    if not check_ollama_available():
        print(f"Cannot connect to Ollama at {config['ollama_url']}")
        if not args.skip_pull:
            if pull_model():
                print("Model pulled successfully")
            else:
                print("Failed to pull model")
                sys.exit(1)
        else:
            sys.exit(1)

    print("Collecting source files...")
    files = get_source_files(repo_path)
    print(f"Found {len(files)} source files")

    if not files:
        print("No source files found to analyze")
        sys.exit(1)

    if not args.warmup:
        print("Warming up model (first request may be slow)...")
        warmup_model()

    analysis = analyze_with_ollama(files, repo_name)

    if args.output:
        output_file = args.output
        report_dir = str(Path(output_file).parent) if args.output else None
    else:
        date_str = datetime.now().strftime("%m%d%y")
        report_dir = os.path.join(
            os.getcwd(), "security_reports", f"{date_str}-{repo_name}"
        )
        os.makedirs(report_dir, exist_ok=True)
        output_file = os.path.join(report_dir, "security_report.md")

    report = generate_report(analysis, repo_name, repo_path, files, report_dir)

    with open(output_file, "w") as f:
        f.write(report)

    print(f"\nReport written to: {output_file}")

    vulnerabilities = analysis.get("vulnerabilities", [])
    print(f"\nFound {len(vulnerabilities)} vulnerabilities")

    for vuln in vulnerabilities:
        print(
            f"  [{vuln.get('severity', '?')}] {vuln.get('cwe_id', 'N/A')} - {vuln.get('name', 'Unknown')}"
        )


if __name__ == "__main__":
    main()
