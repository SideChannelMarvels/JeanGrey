# Jean Grey

*Jean can manipulate other people's minds easily, achieving a variety of effects. The range at which she can perform these feats is greatly increased while she is accessing the Phoenix Force.*

JeanGrey is a set of tools to perform differential fault analysis attacks (DFA).

Currently it contains the following tools:

  * [phoenixAES](phoenixAES) for AES DFA attacks
  * [phoenixAES-yifan](phoenixAES-yifan) for AES DFA attacks, a variant by Yifan Lu which will try all possible combinations of ciphertexts. Slower but handy when phoenixAES fails.

Similar tools:

  * [DFA-AES by Andy Russon](https://github.com/arusson/dfa-aes), handy when pairs of correct and faulty ciphertexts are known but too few and require bruteforcing among the key bytes candidates (R8 or R9).
  * [AES-128 and DES DFA by Nicolas Manichon](https://github.com/balayette/fault), untested.
  * [DFA-AES by Philipp Jovanovic](https://github.com/Daeinar/dfa-aes), computes AES-128 key candidates from one single fault in round8.
