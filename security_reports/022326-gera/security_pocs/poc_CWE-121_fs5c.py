#!/usr/bin/env python3
"""
Proof of Concept for CWE-121 - Stack Buffer Overflow
Severity: High
File: fs5.c
Line: 8

Description:
The program uses snprintf() with user-controlled format string, potentially leading to stack buffer overflow.

Evidence:
snprintf(buf,sizeof buf,argc[1]); - User-controlled format string

Impact:
Format string vulnerability can lead to stack corruption and potential code execution

How to Test:
Run: ./fs5 $(python3 -c "print('%n%100s')")
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
