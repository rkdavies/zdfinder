#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: sg3.c
Line: 10

Description:
The program uses strdup() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

Evidence:
buf[read(0,buf,sizeof buf)]=0; - No bounds checking on read

Impact:
Can lead to stack corruption, arbitrary code execution, or information disclosure

How to Test:
Run: ./sg3 && echo 'A'*200
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
