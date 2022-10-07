## phoenixSM4: a tool to perform differential fault analysis attacks (DFA) against SM4

Currently phoenixSM4 contains the following combined attacks:

  * Simple DFA at round 32 as explained in section 4.3 of https://eprint.iacr.org/2010/063.
  * DFA at round 31 to recover 4 round key bytes. Reference: https://ieeexplore.ieee.org/document/4402669
  * Automatically rewinds a round when a full round key is found.

## Installation

There is no dependencies, it requires only Python 3.

```
python3 -m pip install phoenixSM4
```

## Usage
It takes a file of recorded outputs, optionally preceded by inputs (which will be ignored).
First record must be with the correct output, to be used as reference.  

```python
#!/usr/bin/env python
import phoenixSM4

with open('tracefile', 'wb') as t:
    t.write("""
09325c4853832dcb9337a5984f671b9a
c8141f5697ac1e7021f567e84f671b92
dcfa486ad93d750d4950c2254f671b1a
05f91951f692aee2bca07947d3e1aeec
ab3854a661620285448b8ccd0fda1609
""".encode('utf8'))

phoenixSM4.crack_file('tracefile')
```

```
Round key 32 found:
12A02491
Round key 31 found:
E572CF01
Round key 30 found:
96342962
Round key 29 found:
54368D42
[2435096594, 30372581, 1646867606, 1116550740]
```