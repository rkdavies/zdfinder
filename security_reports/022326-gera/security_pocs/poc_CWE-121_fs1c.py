#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: fs1.c
Line: 12

Description:
The program uses printf() with format string vulnerabilities, potentially leading to stack buffer overflow.

Evidence:
printf("%s%hn\n",buf,plen); - Format string with %hn specifier

Impact:
Format string vulnerability can lead to stack corruption and potential code execution

How to Test:
Run: ./fs1 $(python3 -c "print('%n%100s')")
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
