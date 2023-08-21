# AES known-key fault-injection analysis tool

When you know the key being used, you can compare side by side a correct and faulty execution and see where the fault was likely injected, i.e. at which moment both executions differ by only few bitflips.

The tool displays how many bits are different between correct and faulty execution on the last operation then rewinds it until it finds a minimum in the number of bitflips.

## Examples

### Faulted AES encryption

Rewinding (=decrypting) the faulty output `50473981ae8fcc3c6320af9135023786` and the correct output `c6a13b37878f5b826f4f8162a1c8d879` of an AES encryption, knowing the key was `000102030405060708090a0b0c0d0e0f`:
```
./aes-known-key-fault-analysis.py encryption 000102030405060708090a0b0c0d0e0f 50473981ae8fcc3c6320af9135023786 c6a13b37878f5b826f4f8162a1c8d879
Cipher  :  4  5  1  5  3 ..  5  6  2  6  4  6  3  4  7  8
SBox  10:  4  1  4  4  5  3  4  3  3 ..  3  3  2  5  6  4
MixC   9:  6  4  4  3  6  4  3  4  3  5  4  3  6  1  5  3
SBox   9:  6  3  6  3  4  3  5  1  5  4  3  6  4  1  5  6
MixC   8:  4  5  2  5  1  7  3  2  1  4  4  3  6  2  4  4
SBox   8:  3  3  6  3  4  3  3  4  6  3  3  3  3  4  4  3
MixC   7: .. .. ..  3 .. ..  4 .. ..  3 .. ..  4 .. .. ..
SBox   7: .. .. .. .. .. .. .. .. .. .. .. ..  5  5  2  2
MixC   6: .. .. .. .. .. .. .. .. .. .. .. .. ..  2 .. ..
SBox   6: ..  5 .. .. .. .. .. .. .. .. .. .. .. .. .. ..
```
We see the fault occurred likely *before* the MixColumn operation of round 6, with 2 bitflips.

### Faulted AES decryption

Inversely, we can rewind (=encrypt) the faulty output `16B6ED4B37077FF1239B7341A23D0591` and the correct output `00000000000000000000000000000000` of an AES decryption, knowing the key was `000102030405060708090a0b0c0d0e0f`:
```
./aes-known-key-fault-analysis.py decryption 000102030405060708090a0b0c0d0e0f 16B6ED4B37077FF1239B7341A23D0591 00000000000000000000000000000000
Plain   :  3  5  6  4  5  3  7  5  3  5  5  2  3  5  2  3
ISBox  1:  2  5  3  3  3  3  5  4  3  4  4  7  3  5  1  6
MixC   1:  2  2  2  5  3  5  5  6  4  2  5  4  4  3  5  4
ISBox  2:  5  5  2  6  5  4  6  2  4  5  4  2  4  2  3  5
MixC   2:  5  3  6  6  4  3  4  6  4  4  2 ..  4  4  2  5
ISBox  3:  3  3  4  2  3  5  6  5  6  5  4 ..  3  4  4  5
MixC   3:  2  4  2  3  3  3  5  5  2  3  3  3  3  4  5  6
ISBox  4:  7  5  2  4  2  3  5  7  2  6  3  3  2  4  3  4
MixC   4: .. ..  3 .. .. .. ..  3  5 .. .. .. ..  5 .. ..
ISBox  5: .. ..  2 .. .. .. ..  3  3 .. .. .. ..  3 .. ..
MixC   5: .. .. .. .. .. .. .. .. ..  1 .. .. .. .. .. ..
ISBox  6: .. .. .. .. .. .. .. .. ..  4 .. .. .. .. .. ..
```
We see the fault occurred likely *before* the MixCol operation of round 5, with 1 bitflip.

AES implementation based on https://github.com/boppreh/aes, itself expanded from Bo Zhu's (http://about.bozhu.me)
AES-128 implementation at https://github.com/bozhu/AES-Python
