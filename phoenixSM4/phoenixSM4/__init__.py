#########################################################################
# phoenixSM4 is a Python 3 library to apply                             #
# a Differential Fault Analysis attack on faulty outputs                #
#                                                                       #
# Copyright (C) 2022                                                    #
# Original author:   Sylvain Pelissier <sylvain.pelissier@gmail.com>    #
# Based on: https://github.com/guojuntang/sm4_dfa
# Contributors:                                                         #
#                                                                       #
# This program is free software: you can redistribute it and/or modify  #
# it under the terms of the GNU General Public License as published by  #
# the Free Software Foundation, either version 3 of the License, or     #
# any later version.                                                    #
#                                                                       #
# This program is distributed in the hope that it will be useful,       #
# but WITHOUT ANY WARRANTY; without even the implied warranty of        #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         #
# GNU General Public License for more details.                          #
#                                                                       #
# You should have received a copy of the GNU General Public License     #
# along with this program.  If not, see <http://www.gnu.org/licenses/>. #
#########################################################################

blocksize = 16
xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))
rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)
get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))
get_uint32_le = lambda key_data:((key_data[3] << 24) | (key_data[2] << 16) | (key_data[1] << 8) | (key_data[0]))
put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]
put_uint32_le = lambda n:[((n)&0xff), ((n>>8)&0xff), ((n>>16)&0xff), ((n>>24)&0xff)]
l_inv = lambda c: c ^ rotl(c, 2) ^ rotl(c, 4) ^ rotl(c, 8) ^ rotl(c, 12) ^ rotl(c, 14) ^ rotl(c, 16) ^ rotl(c, 18) ^ rotl(c, 22) ^ rotl(c, 24) ^ rotl(c, 30)
int2bytes = lambda state, size: (state).to_bytes(size, byteorder = 'big', signed = False)
bytes2int = lambda state: int.from_bytes(state, 'big', signed=False)
singleState = lambda a, index: (a >> (index * 8)) &  0xff
getSlices = lambda block:[(block >> (32 * i) & 0xffffffff )for i in range(0,4)]
byte2slices = lambda state:[get_uint32_be(state[i * 4 : (i + 1) * 4 ]) for i in range(4)]
find_candidate_index = lambda diff: [i  for i in range(4, len(diff)) if diff[i] != b'\x00'][0] % 4

SM4_ENCRYPT = 0
SM4_DECRYPT = 1

SM4_BOXES_TABLE = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,
    0x05,0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,
    0x06,0x99,0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,
    0xcf,0xac,0x62,0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,
    0x75,0x8f,0x3f,0xa6,0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,
    0x19,0xe6,0x85,0x4f,0xa8,0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,
    0x0f,0x4b,0x70,0x56,0x9d,0x35,0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,
    0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,
    0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,
    0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,0xe0,0xae,0x5d,0xa4,0x9b,0x34,
    0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,0x1d,0xf6,0xe2,0x2e,0x82,
    0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,0xd5,0xdb,0x37,0x45,
    0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,0x8d,0x1b,0xaf,
    0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,0x0a,0xc1,
    0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,0x89,
    0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,
    0x48,
]

def check_diff(diffmap, n):
    for i in range(n-1):
        if diffmap[i] != i:
            return False
    return True

def gen_diff_table():
    """
    Generate the differential table.
    :returns: a differential table contains all the x satisfying S(x ^ \alpha) ^ S(x) = \beta
    """
    #Find {x: S(x) ^ S(x ^ diff_in) = diff_out } for all diff_in and diff_out
    IN_Table = [[[] for i in range(2 ** 8)]for j in range(2 ** 8)]
    for diff_in in range(1,2 ** 8):
        for x in range(2 ** 8):
            diff_out = SM4_BOXES_TABLE[x] ^ SM4_BOXES_TABLE[diff_in ^ x]
            IN_Table[diff_in][diff_out].append(x)

    return IN_Table

IN_Table = gen_diff_table()

def f_function( x0, x1, x2, x3, rk):
    """
    SM4 f function.
    :param x0, x1, x2, x3, rk: 32 bits unsigned value;
    :returns: c
    """
    ka = x1 ^ x2 ^ x3 ^ rk
    b = [0, 0, 0, 0]
    a = put_uint32_be(ka)
    b[0] = SM4_BOXES_TABLE[a[0]]
    b[1] = SM4_BOXES_TABLE[a[1]]
    b[2] = SM4_BOXES_TABLE[a[2]]
    b[3] = SM4_BOXES_TABLE[a[3]]
    bb = get_uint32_be(b[0:4])
    c = bb ^ (rotl(bb, 2)) ^ (rotl(bb, 10)) ^ (rotl(bb, 18)) ^ (rotl(bb, 24))

    return (x0 ^ c)

def rewind(state, lastroundkeys=None):
    """
    Rewinds a SM4 round

    :param state: SM4 state, as 16 bytes
    :param lastroundkeys: a list of 32-bit words round keys for the rounds to rewind.
    :returns: SM4 state one round earlier
    """
    output = []
    ulbuf = [0] * 36
    ulbuf[0:4] = byte2slices(state)

    if lastroundkeys == None:
        return state

    round_num = len(lastroundkeys)

    for idx in range(round_num):
        ulbuf[idx + 4] = f_function(ulbuf[idx], ulbuf[idx + 1], ulbuf[idx + 2], ulbuf[idx + 3], lastroundkeys[idx])

    output += put_uint32_be(ulbuf[round_num])
    output += put_uint32_be(ulbuf[round_num + 1])
    output += put_uint32_be(ulbuf[round_num + 2])
    output += put_uint32_be(ulbuf[round_num + 3] )
    return bytes(output)

def crack_round(roundFaultList, ref, last_round_key = None, verbose=1):
    """
    Crack the round key from the faulty cipher and correct cipher

    :param roundFaultList: the list with faulty ciphers, as byte list
    :param ref the correct: cipher, as byte
    :param last_round_key:  for decrypting the faulty cipher and correct cipher if not empty, as int list
    :param verbose: verbosity level
    :return: the next round key or None
    """
    if last_round_key is not None and len(last_round_key) != 0:
        """
            if last round key is not empty: require to decrypt the cipher by it
        """
        if verbose>1:
            print(f"Rewinding round.")
        
        ref = rewind(ref, last_round_key)
        roundFaultList = [ rewind(faulted, last_round_key) for faulted in roundFaultList]

    return crack_bytes(roundFaultList, ref, verbose)

def check(ref, output, verbose=1):
    """
    Checks an output against a reference.

    :param ref: the reference
    :param output: potentially faulty output
    :param verbose: verbosity level, prints only if verbose>2
    :returns: the index for cracking key bytes
    """
    if output == ref:
        if verbose>2:
            print("FI: no impact : ")
        return None
    diff = xor(output, ref)
    #record the index of difference
    diffmap = [i for i in range(len(diff)) if diff[i] != 0]
    diffsum = len(diffmap)
    """
    SM4 always put the updated data at left hand side,
    so the fist four diff will never be equal to 0
    """
    if diffsum == 5 or diffsum == 8 or diffsum == 9 or diffsum == 12 or diffsum == 13  :
        """
            The target cipher in round 31 for analyzing the round key always contains five bytes difference
            And the index of the four/eight/twelve difference indicates the position of the S-BOX for cracking the key byte.
        """
        if  check_diff(diffmap, diffsum):
            if diffsum == 5:
                if verbose > 2:
                    print(f"FI: good candidate for round N (({diffsum:{2}} bytes)): \t{output.hex()} {bytes(diff).hex()}")
                    print(bytes(diff).hex())
                index = [(3 - diffmap[diffsum - 1] % 4)]
            elif diffsum == 9 or diffsum == 8:
                if verbose > 2:
                    print(f"FI: good candidate for round N-1 (({diffsum:{2}} bytes)): \t{output.hex()} {bytes(diff).hex()}")
                index = [0, 1, 2, 3]
            elif diffsum == 13 or diffsum ==12:
                if verbose > 2:
                    print(f"FI: good candidate for round N-2 (({diffsum:{2}} bytes)): \t{output.hex()} {bytes(diff).hex()}")
                index = [0, 1, 2, 3]
            else:
                return []
            return index
        else:
            if verbose > 2:
                print(f"FI: wrong candidate ({diffsum:{2}} bytes): \t\t{output.hex()} {bytes(diff).hex()}")
            return []
    elif diffsum<5:
        if verbose > 2:
            print(f"FI: too few impact ({diffsum:{2}} bytes): \t\t\t{output.hex()} {bytes(diff).hex()}")

        return []
    else:
        if verbose > 2:
            print(f"FI: too much impact ({diffsum:{2}} bytes): \t\t{output.hex()} {bytes(diff).hex()}")
        return []

def get_candidates(faultcipher, ref, index, verbose=1):
    """
    Get the key candidates
    return the set of possible key bytes at this index
    """
    global IN_Table
    faultcipher = bytes2int(faultcipher)
    ref = bytes2int(ref)
    ref_slice = getSlices(ref)
    fault_slice = getSlices(faultcipher)
    delta_C =  xor(ref_slice, fault_slice)[3]
    delta_B = l_inv(delta_C)
    A = ref_slice[0] ^ ref_slice[1] ^ ref_slice[2]
    A_star = fault_slice[0] ^ fault_slice[1] ^ fault_slice[2]
    result = [None] * 4
    for i in index:
        alpha = singleState(A ^ A_star, i)
        beta = singleState(delta_B, i)
        r = IN_Table[alpha][beta]
        if r:
            result[i] = [singleState(A, i) ^ x for x in r]
        else:
            if verbose > 2:
                print("Error: empty key candidate!")
    return result

def crack_bytes(roundFaultList, ref, verbose=1):
    """
    Tries to crack a round key given faulty outputs.

    :param roundFaultList: list of faulty outputs, as bytes
    :param ref: reference output, as bytes
    :param verbose: verbosity level
    :returns: cracked round key as int or None
    """
    candidates = [None] * 4
    key = [None] * 4

    for faultCipher in roundFaultList:
        # Check if key is found
        if key[0] != None and key[1] != None and key[2] != None and key[3] != None:
            break
        found_key = False
        index = check(ref, faultCipher, verbose=verbose)
        if len(index) == 0:
            continue
        if verbose > 3:
            print(f"Key index at {index}")

        c = get_candidates(faultCipher, ref, index,  verbose)
        for i in index:
            if key[i] is not None:
                continue    
            if c[i] is None:
                continue
            if not candidates[i]:
                #initial candidate state 
                candidates[i] = c[i]
            else:
                candidates[i] = list(set(candidates[i]) & set(c[i]))
                # get the exact key
                if (len(candidates[i]) == 1):
                    key[i] = candidates[i][0]
                    found_key = True
                elif len(candidates[i]) == 0:
                    # Something wrong happened we reset the candidate list.
                    candidates[i] = None

        if verbose > 1 and found_key:
            print("Round key bytes recovered:")
            print(''.join(["%02X" % x if x is not None else ".." for x in key]))
        if verbose > 2:
            print(f"Key candidates:{candidates}")
    # Check whether all key bytes have been recovered
    if None in key:
        return None
    return get_uint32_le(key) 

def crack_file(filename, lastroundkeys=None, verbose=1):
    """
    Tries to crack round keys given faulty outputs glitched and stored in a file

    :param filename: the filename of a file containing the output reference on the first line and glitched outputs on next lines, as hex strings
    :param lastroundkeys: a list of round keys for the rounds to rewind, as 32-bit int.
    :param verbose: verbosity level
    :returns: cracked round keys as hexstring or None
    """
    ref = None
    faults = []

    if lastroundkeys == None:
        lastroundkeys = []

    for line in open(filename):
        if len(line.split())==1:
            # only output available
            o = bytes.fromhex(line.strip())
            assert len(o) == blocksize
            if ref is None:
                ref = o
            else:
                faults.append(o)
        elif len(line.split()) == 2:
            i,o = line.split()
            i,o = bytes.fromhex(i), bytes.fromhex(o)
            assert len(i) == len(o) == blocksize
            if ref is None:
                ref = o
            else:
                faults.append(o)
        else:
            continue
    
    last_round_key = None
    round = 32 - len(lastroundkeys)
    while len(lastroundkeys) < 4:
        last_round_key = crack_round(faults, ref, lastroundkeys, verbose)
        if last_round_key == None:
            break
        else:
            print(f"Round key {round} found:")
            roundkey = ''.join(["%02X" % x for x in put_uint32_le(last_round_key)])
            print(roundkey)
            lastroundkeys.append(last_round_key)
            round -= 1

    return lastroundkeys