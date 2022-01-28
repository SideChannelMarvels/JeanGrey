Scripts by Yifan Lu to crack the PlayStation Vita keys.

* https://yifan.lu/2019/02/22/attacking-hardware-aes-with-dfa/
* https://yifan.lu/images/2019/02/Attacking_Hardware_AES_with_DFA.pdf
* https://github.com/TeamMolecule/f00dsimpleserial/tree/master/scripts/dfa_crack

To be used for injections before the last two MixColumns.

* `crack_all.py` will try all pair combinations of faulty outputs.
* `crack_all_slow.py` will try all fauly outputs as the good reference as well. This sounds strange but can work on situations where there is an additional static fault across several executions. See the paper.
