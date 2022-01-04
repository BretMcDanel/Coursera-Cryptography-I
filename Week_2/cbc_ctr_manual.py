#!/usr/bin/env python3

from Cryptodome.Cipher import AES


def xor_bytes(bytes_a, bytes_b):
    """XOR two byte arrays against each other byte by byte

    Args:
      bytes_a: bytearray to XOR
      bytes_b: bytearray to XOR

    Returns:
      bytearray of XORed values
    """
    return bytes(x ^ y for (x, y) in zip(bytes_a, bytes_b))

def cbc_decrypt(encdata):
    """Manually decrypt CBC mode using ECB

    Args:
      encdata: list ( key, ciphertext )

    Returns:
      bytearray of decrypted data
    """

    key = encdata[0]
    iv = encdata[1][:AES.block_size]
    ciphertext = encdata[1][AES.block_size:]
    cipher = AES.new(key, AES.MODE_ECB)

    if len(ciphertext) % AES.block_size != 0:
        raise Exception("Short block")


    # Loop through blocks
    block_idx = 0
    output = bytearray()
    while block_idx < len(ciphertext):
        # decrypt then XOR IV with m[0] or prev output block with m[n]
        block = cipher.decrypt(ciphertext[block_idx:block_idx + AES.block_size])

        if block_idx:
            output.extend(xor_bytes(block, ciphertext[block_idx - AES.block_size:block_idx]))
        else:
            output.extend(xor_bytes(block, iv))

        block_idx += AES.block_size

    # remove padding
    padding_bytes = output[len(output)-1]
    return output[:len(output)-padding_bytes]

def cbc_encrypt(plaintext, iv, key):
    """Manually encrypt CBC mode using ECB

    Args:
      plaintext: bytearray to encrypt
      key: the key to encrypt with
      iv: the IV to use

    Returns:
      bytearray of encrypted data
    """
    ciphertext = iv
    cipher = AES.new(key, AES.MODE_ECB)

    # pad to a block size
    pad = len(plaintext) % AES.block_size
    if pad == 0:
        pad = AES.block_size
    else:
        pad = AES.block_size - pad
        
    plaintext.extend([pad]*pad)

    # loop through plaintext blocks
    block_idx = 0
    while block_idx < len(plaintext):
        # XOR IV with m[0] or prev output block with m[n] then encrypt
        block = plaintext[block_idx:block_idx + AES.block_size]

        if block_idx:
            block = xor_bytes(result, plaintext[block_idx:block_idx + AES.block_size])
        else:
            block = xor_bytes(iv, plaintext[block_idx:block_idx + AES.block_size])

        result = cipher.encrypt(block)
        ciphertext.extend(result)
        block_idx += AES.block_size

    return ciphertext

def increment_bytes(bytestr, inc, size, endian):
    """Increment bytearray

    Args:
      bytestr: the bytes to increment
      inc: the value to increment
      size: the size of the bytes
      endian: big or little

    Returns:
      bytearray of the incremented value
    """

    i = int.from_bytes(bytestr, endian)
    i += inc
    return i.to_bytes(size, endian)

def ctr_decrypt(encdata):
    """Manually decrypt CTR mode using ECB

    Args:
      encdata: list ( key, ciphertext )

    Returns:
      bytearray of decrypted data
    """

    key = encdata[0]
    iv = encdata[1][:AES.block_size]
    ciphertext = encdata[1][AES.block_size:]

    # Loop through blocks
    block_idx = 0
    output = bytearray()
    while block_idx < len(ciphertext):
        # XOR c[n] with F(k,iv++)
        block = ciphertext[block_idx:block_idx+min(AES.block_size, len(ciphertext)-block_idx)]
        output.extend(xor_bytes(AES.new(key, AES.MODE_ECB).encrypt(iv), block))
        iv = increment_bytes(iv, 1, AES.block_size, "big")
        block_idx += AES.block_size

    return output

def ctr_encrypt(plaintext, iv, key):
    """Manually encrypt CTR mode using ECB

    Args:
      plaintext: bytearray to encrypt
      key: the key to encrypt with
      iv: the IV to use

    Returns:
      bytearray of encrypted data
    """
    cipher = AES.new(key, AES.MODE_ECB)

    # Loop through blocks
    block_idx = 0
    output = bytearray(iv)
    while block_idx < len(plaintext):
        # XOR m[n] with f(k,iv++)
        block = plaintext[block_idx:block_idx+min(AES.block_size, len(plaintext)-block_idx)]
        output.extend(xor_bytes(cipher.encrypt(iv), block))
        iv = increment_bytes(iv, 1, AES.block_size, "big")
        block_idx += AES.block_size
    return output



CIPHERTEXTS = [
    [
        # CBC mode
        "140b41b22a29beb4061bda66b6747e14",
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    ],
    [
        # CBC mode
        "140b41b22a29beb4061bda66b6747e14",
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    ],
    [
        # CTR mode (standard)
        "36f18357be4dbd77f050515c73fcf9f2",
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    ],
    [
        # CTR mode (nonce)
        "36f18357be4dbd77f050515c73fcf9f2",
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    ]
]


# Convert the key and ciphertext to binary
for ct_idx, ct in enumerate(CIPHERTEXTS):
    CIPHERTEXTS[ct_idx] = [bytearray.fromhex(ct[0]), bytearray.fromhex(ct[1])]


print(cbc_decrypt(CIPHERTEXTS[0]).decode())
print(cbc_decrypt(CIPHERTEXTS[1]).decode())
print(ctr_decrypt(CIPHERTEXTS[2]).decode())
print(ctr_decrypt(CIPHERTEXTS[3]).decode())

test_data = CIPHERTEXTS[0]
key = test_data[0]
iv = test_data[1][:AES.block_size]
result = cbc_encrypt(cbc_decrypt(test_data), iv, key)

if result == test_data[1]:
    print("TEST: CBC encryption - passed")
else:
    print("TEST: CBC encryption - failed")
    print(f"Expected:\n{test_data[1].hex(' ')}")
    print(f"Received:\n{result.hex(' ')}")


test_data = CIPHERTEXTS[2]
key = test_data[0]
iv = test_data[1][:AES.block_size]
result = ctr_encrypt(ctr_decrypt(test_data), iv, key)

if result == test_data[1]:
    print("TEST: CTR encryption - passed")
else:
    print("TEST: CTR encryption - failed")
    print(f"Expected:\n{test_data[1].hex(' ')}")
    print(f"Received:\n{result.hex(' ')}")



