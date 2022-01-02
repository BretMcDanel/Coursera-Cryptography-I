#!/usr/bin/env python3
"""
From the assignment
Hint: XOR the ciphertexts together, and consider what happens when a space is
      XORed with a character in [a-zA-Z].
--
Hint:
[A-Z] ^ 'space' = [a-z]
[a-z] ^ 'space' = [A-Z]
Additionally:
[A-Z] ^ [a-z] = 'space' (for any character where case is the only difference)


Solution:
XOR each ciphertext against the remaining ciphertexts.  Do this for all ciphertexts
    C1 ^ C2 = M1^k ^ M2^k = M1^M2

For each byte M1^Mn XOR against space (0x20)
    If result is between 0x40 and 0x7E there is probably a space in one of the two strings
    Differentiate which message has the space by comparing that position in all sets
        if the majority have a space it is probably the current string
        -- consider if both have a space (M1=M2 then M1^M2=0)
        -- consider if neither have a space (result will be out of range)
    If current string has a space XOR ciphertext[n] and 0x20 to get the key for that position

For any missing key values manually compute
    The key must make sense for all messages
    Use recovered letters to guess what the missing letter is
"""

def xor_bytes(bytes_a, bytes_b):
    """XOR two byte arrays against each other byte by byte

    Args:
      bytes_a: bytearray to XOR
      bytes_b: bytearray to XOR

    Returns:
      bytearray of XORed values
    """
    return bytes(x ^ y for (x, y) in zip(bytes_a, bytes_b))


#The values were provided as ASCII hex
CIPHERTEXTS = [
    # target ciphertext (decrypt this one)
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0"\
    "a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904",

    # ciphertext #1
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5"\
    "b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7"\
    "dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef"\
    "3e",

    # ciphertext #2
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5"\
    "ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2"\
    "cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",

    # ciphertext #3
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7"\
    "b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8"\
    "d661cb",

    # ciphertext #4
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1"\
    "ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7"\
    "da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7"\
    "229be6636aaa",

    # ciphertext #5
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1"\
    "e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95"\
    "d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",

    # ciphertext #6
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9"\
    "a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4"\
    "cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe5"\
    "2ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",

    # ciphertext #7
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1"\
    "ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2"\
    "d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e7"\
    "2287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9"\
    "a4ce",

    # ciphertext #8
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9"\
    "e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2"\
    "ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",

    # ciphertext #9
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeec"\
    "a709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2"\
    "c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f8"\
    "22c9ed6d76e48b63ab15d0208573a7eef027",

    # ciphertext #10
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0"\
    "a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2"\
    "cb2a83"
]


# Key length is the length of the target message
KEYSIZE = int(len(CIPHERTEXTS[0])>>1)
KEY = [0]*KEYSIZE

for idx, cipher in enumerate(CIPHERTEXTS):
    # Build the message list with byte values of our cipher text
    # truncate to the length of the target message to avoid processing data we dont care about
    CIPHERTEXTS[idx] = bytearray.fromhex(cipher[:KEYSIZE<<1])



for c1_idx, c1 in enumerate(CIPHERTEXTS):
    # for each string XOR with all others
    cipher_pair = []
    for c2_idx, c2 in enumerate(CIPHERTEXTS):
        if c1_idx != c2_idx:
            cipher_pair.append(xor_bytes(c1, c2))

    # look for spaces in the message
    for cnt in range(min(len(c1), KEYSIZE)):
        if KEY[cnt] == 0:
            # Do not process this index if the key value is known
            possible_space = 0
            for pair_idx, pair_bytes in enumerate(cipher_pair):
                if ((pair_bytes[cnt] >= 0x40 and pair_bytes[cnt] <= 0x7e)
                        or (pair_bytes[cnt] == 0)):
                    possible_space += 1

            if possible_space >= 8:
                # high probability of a space in this string
                KEY[cnt] = c1[cnt]^0x20

KEY[7] = 0xcc # no space in plaintext
KEY[21] = 0x7f # no space in plaintext
KEY[25] = 0x7f # no space in plaintext
KEY[32] = 0x69 # no space in plaintext
KEY[36] = 0x19 # no space in plaintext
KEY[49] = 0x63 # , collided with the space in #8

# print the target answer
print(f"The exercise answer is: '{xor_bytes(CIPHERTEXTS[0], KEY).decode()}'\n")

# print the other CIPHERTEXTS
print("Ciphertexts")
for msg_idx in range(1, len(CIPHERTEXTS)):
    print(f"{msg_idx:>2}: '{(xor_bytes(CIPHERTEXTS[msg_idx], KEY)[:KEYSIZE]).decode()}'")
