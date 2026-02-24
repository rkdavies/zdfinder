#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: n5.c
Line: 15

Description:
The program uses malloc() with user-controlled size without bounds checking, leading to potential heap overflow.

Evidence:
args = malloc(count*sizeof(char*)); - User-controlled size without validation

Impact:
Heap overflow can lead to memory corruption and potential code execution

How to Test:
Run: echo '1000000' | ./n5
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
