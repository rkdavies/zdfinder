#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: abo5.c
Line: 12

Description:
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

Evidence:
strcpy(buf,argc[1]); - No bounds checking on input

Impact:
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

How to Test:
Run: ./abo5 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"
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
