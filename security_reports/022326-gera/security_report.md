# Security Analysis Report

**Repository:** gera
**Path:** /Users/rkdavies/git/gera
**Date:** 2026-02-23 16:33:04
**Model:** huihui_ai/qwen3-coder-abliterated:30b
**Files Analyzed:** 82

---

## Summary

**Total Vulnerabilities Found:** 40
- Critical: 0
- High: 40
- Medium: 0
- Low: 0

---

## High Severity Vulnerabilities

### 1. Stack Buffer Overflow (CWE-121)

**File:** e3.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./e3 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_e3c.py`
---

### 2. Stack Buffer Overflow (CWE-121)

**File:** s4.c
**Line:** 9

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./s4 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_s4c.py`
---

### 3. Stack Buffer Overflow (CWE-121)

**File:** fs2.c
**Line:** 7

**Description:**
The program uses snprintf() with format string vulnerabilities, potentially leading to stack buffer overflow.

**Evidence:**
```
snprintf(buf,sizeof buf,"%s%c%c%hn",argc[1]); - Format string with %hn specifier
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./fs2 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_fs2c.py`
---

### 4. Stack Buffer Overflow (CWE-121)

**File:** stack2.c
**Line:** 8

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and overwrite cookie

**How to Test:**
Run: ./stack2 && echo 'A'*100

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_stack2c.py`
---

### 5. Stack Buffer Overflow (CWE-121)

**File:** abo7.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo7 $(python3 -c "print('A'*300")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo7c.py`
---

### 6. Stack Buffer Overflow (CWE-121)

**File:** abo3.c
**Line:** 14

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo3 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo3c.py`
---

### 7. Stack Buffer Overflow (CWE-121)

**File:** n4.c
**Line:** 14

**Description:**
The program uses alloca() with user-controlled size without bounds checking, leading to potential stack buffer overflow.

**Evidence:**
```
args = alloca(count*sizeof(char*)); - User-controlled size without validation
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If count is set to a large value, alloca() will allocate excessive stack space

**How to Test:**
Run: echo '1000000' | ./n4

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_n4c.py`
---

### 8. Stack Buffer Overflow (CWE-121)

**File:** abo9.c
**Line:** 10

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(pbuf1); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 256 bytes will overflow pbuf1 and potentially overwrite other variables

**How to Test:**
Run: ./abo9 && echo 'A'*300

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo9c.py`
---

### 9. Stack Buffer Overflow (CWE-121)

**File:** e4.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./e4 $(python3 -c "print('A'*300")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_e4c.py`
---

### 10. Stack Buffer Overflow (CWE-121)

**File:** s3.c
**Line:** 10

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./s3 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_s3c.py`
---

### 11. Stack Buffer Overflow (CWE-121)

**File:** stack1.c
**Line:** 8

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and overwrite cookie

**How to Test:**
Run: ./stack1 && echo 'A'*100

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_stack1c.py`
---

### 12. Stack Buffer Overflow (CWE-121)

**File:** fs1.c
**Line:** 12

**Description:**
The program uses printf() with format string vulnerabilities, potentially leading to stack buffer overflow.

**Evidence:**
```
printf("%s%hn\n",buf,plen); - Format string with %hn specifier
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./fs1 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_fs1c.py`
---

### 13. Stack Buffer Overflow (CWE-121)

**File:** abo10.c
**Line:** 10

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 256 bytes will overflow buf and potentially overwrite other variables

**How to Test:**
Run: ./abo10 && echo 'A'*300

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo10c.py`
---

### 14. Stack Buffer Overflow (CWE-121)

**File:** abo4.c
**Line:** 16

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo4 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100") $(python3 -c "print('C'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo4c.py`
---

### 15. Stack Buffer Overflow (CWE-121)

**File:** n3.c
**Line:** 14

**Description:**
The program uses alloca() with user-controlled size without bounds checking, leading to potential stack buffer overflow.

**Evidence:**
```
args = alloca(count*sizeof(char*)); - User-controlled size without validation
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If count is set to a large value, alloca() will allocate excessive stack space

**How to Test:**
Run: echo '1000000' | ./n3

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_n3c.py`
---

### 16. Stack Buffer Overflow (CWE-121)

**File:** stack5.c
**Line:** 8

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and overwrite cookie

**How to Test:**
Run: ./stack5 && echo 'A'*100

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_stack5c.py`
---

### 17. Stack Buffer Overflow (CWE-121)

**File:** fs5.c
**Line:** 8

**Description:**
The program uses snprintf() with user-controlled format string, potentially leading to stack buffer overflow.

**Evidence:**
```
snprintf(buf,sizeof buf,argc[1]); - User-controlled format string
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./fs5 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_fs5c.py`
---

### 18. Stack Buffer Overflow (CWE-121)

**File:** e5.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./e5 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_e5c.py`
---

### 19. Stack Buffer Overflow (CWE-121)

**File:** s2.c
**Line:** 10

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./s2 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_s2c.py`
---

### 20. Stack Buffer Overflow (CWE-121)

**File:** s1.c
**Line:** 11

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./s1 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_s1c.py`
---

### 21. Stack Buffer Overflow (CWE-121)

**File:** abo5.c
**Line:** 12

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo5 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo5c.py`
---

### 22. Stack Buffer Overflow (CWE-121)

**File:** stack4.c
**Line:** 8

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and overwrite cookie

**How to Test:**
Run: ./stack4 && echo 'A'*100

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_stack4c.py`
---

### 23. Stack Buffer Overflow (CWE-121)

**File:** fs4.c
**Line:** 8

**Description:**
The program uses printf() with format string vulnerabilities, potentially leading to stack buffer overflow.

**Evidence:**
```
printf(buf); - User-controlled format string
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./fs4 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_fs4c.py`
---

### 24. Stack Buffer Overflow (CWE-121)

**File:** abo6.c
**Line:** 11

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo6 $(python3 -c "print('A'*300") $(python3 -c "print('B'*100")"

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo6c.py`
---

### 25. Stack Buffer Overflow (CWE-121)

**File:** fs3.c
**Line:** 7

**Description:**
The program uses snprintf() with format string vulnerabilities, potentially leading to stack buffer overflow.

**Evidence:**
```
snprintf(buf,sizeof buf,"%s%c%c%hn",argc[1]); - Format string with %hn specifier
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./fs3 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_fs3c.py`
---

### 26. Stack Buffer Overflow (CWE-121)

**File:** stack3.c
**Line:** 8

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and overwrite cookie

**How to Test:**
Run: ./stack3 && echo 'A'*100

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_stack3c.py`
---

### 27. Stack Buffer Overflow (CWE-121)

**File:** abo8.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo8 $(python3 -c "print('A'*300")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo8c.py`
---

### 28. Stack Buffer Overflow (CWE-121)

**File:** abo2.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo2 $(python3 -c "print('A'*300")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo2c.py`
---

### 29. Stack Buffer Overflow (CWE-121)

**File:** n5.c
**Line:** 15

**Description:**
The program uses malloc() with user-controlled size without bounds checking, leading to potential heap overflow.

**Evidence:**
```
args = malloc(count*sizeof(char*)); - User-controlled size without validation
```

**Impact:**
Heap overflow can lead to memory corruption and potential code execution

**Proof of Concept:**
If count is set to a large value, malloc() will allocate excessive heap space

**How to Test:**
Run: echo '1000000' | ./n5

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_n5c.py`
---

### 30. Stack Buffer Overflow (CWE-121)

**File:** n2.c
**Line:** 18

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and potentially overwrite other variables

**How to Test:**
Run: ./n2 $(python3 -c "print('A'*100")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_n2c.py`
---

### 31. Stack Buffer Overflow (CWE-121)

**File:** n1.c
**Line:** 18

**Description:**
The program uses gets() without checking buffer bounds, leading to potential stack buffer overflow.

**Evidence:**
```
gets(buf); - gets() is inherently unsafe
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
Input longer than 80 bytes will overflow buf and potentially overwrite other variables

**How to Test:**
Run: ./n1 $(python3 -c "print('A'*100")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_n1c.py`
---

### 32. Stack Buffer Overflow (CWE-121)

**File:** sg4.c
**Line:** 12

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
decrypt(temp,user); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to user exceeds 80 bytes, decrypt() will overwrite adjacent memory in temp array

**How to Test:**
Run: ./sg4 $(python3 -c "print('A'*100")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg4c.py`
---

### 33. Stack Buffer Overflow (CWE-121)

**File:** sg6.c
**Line:** 12

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
decrypt(temp,user); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to user exceeds 80 bytes, decrypt() will overwrite adjacent memory in temp array

**How to Test:**
Run: ./sg6 $(python3 -c "print('A'*100")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg6c.py`
---

### 34. Stack Buffer Overflow (CWE-121)

**File:** sg5.c
**Line:** 15

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
decrypt(temp,user); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to user exceeds 80 bytes, decrypt() will overwrite adjacent memory in temp array

**How to Test:**
Run: ./sg5 $(python3 -c "print('A'*100")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg5c.py`
---

### 35. Stack Buffer Overflow (CWE-121)

**File:** sg3.c
**Line:** 10

**Description:**
The program uses strdup() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
return strdup(buf); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to buf exceeds 128 bytes, strdup() will overwrite adjacent memory

**How to Test:**
Run: ./sg3 $(python3 -c "print('A'*200')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg3c.py`
---

### 36. Stack Buffer Overflow (CWE-121)

**File:** sg2.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,msg); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to msg exceeds 80 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./sg2 $(python3 -c "print('A'*100')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg2c.py`
---

### 37. Stack Buffer Overflow (CWE-121)

**File:** sg1.c
**Line:** 8

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,msg); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to msg exceeds 80 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./sg1 $(python3 -c "print('A'*100')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_sg1c.py`
---

### 38. Stack Buffer Overflow (CWE-121)

**File:** abo1.c
**Line:** 7

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./abo1 $(python3 -c "print('A'*300')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_abo1c.py`
---

### 39. Stack Buffer Overflow (CWE-121)

**File:** e2.c
**Line:** 11

**Description:**
The program uses strcpy() without checking buffer bounds, leading to potential stack buffer overflow when copying user input.

**Evidence:**
```
strcpy(buf,argc[1]); - No bounds checking on input
```

**Impact:**
Buffer overflow can overwrite adjacent stack variables, potentially leading to arbitrary code execution or crash

**Proof of Concept:**
If input to argc[1] exceeds 256 bytes, strcpy() will overwrite adjacent memory in buf array

**How to Test:**
Run: ./e2 $(python3 -c "print('A'*300')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_e2c.py`
---

### 40. Stack Buffer Overflow (CWE-121)

**File:** e1.c
**Line:** 10

**Description:**
The program uses printf() with user-controlled format string, potentially leading to stack buffer overflow.

**Evidence:**
```
printf(argc[1]); - User-controlled format string
```

**Impact:**
Format string vulnerability can lead to stack corruption and potential code execution

**Proof of Concept:**
Input with format specifiers like '%n' can overwrite stack values

**How to Test:**
Run: ./e1 $(python3 -c "print('%n%100s')")

**PoC Script:** `/Users/rkdavies/git/zdfinder/security_reports/022326-gera/security_pocs/poc_CWE-121_e1c.py`
---

---

## Additional Notes

Analyzed 1 chunks. Total vulnerabilities found: 40. Chunk 1: Analysis of the gera repository reveals multiple stack buffer overflow vulnerabilities across various files. The primary issue is the widespread use of unsafe functions like strcpy(), gets(), and printf() with format strings without proper bounds checking. These vulnerabilities can lead to arbitrary code execution, information disclosure, and system compromise. Most of the issues stem from the use of fixed-size buffers without validation of input lengths, particularly in programs that copy user input directly into these buffers.