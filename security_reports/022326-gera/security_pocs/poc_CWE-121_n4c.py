#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: n4.c
Line: 14

Description:
The program uses alloca() with user-controlled size without bounds checking, leading to potential stack buffer overflow.

Evidence:
args = alloca(count*sizeof(char*)); - User-controlled size without validation

Impact:
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

How to Test:
Run: echo '1000000' | ./n4
"""

import os
import sys

def main():
    print("=" * 60)
    print(f"PoC: Stack Buffer Overflow")
    print(f"CWE: CWE-121")
    print("=" * 60)
    
    print("\nThis is a generated proof of concept.")
    print("Review the vulnerability details above and test manually.")
    print("Some vulnerabilities may require specific conditions to exploit.")

if __name__ == "__main__":
    main()
