#!/usr/bin/env python3

import urllib3

def xor_bytes(bytes_a, bytes_b):
    """XOR two byte arrays against each other byte by byte

    Args:
      bytes_a: bytearray to XOR
      bytes_b: bytearray to XOR

    Returns:
      bytearray of XORed values
    """
    return bytes(x ^ y for (x, y) in zip(bytes_a, bytes_b))
    
    
def test_a_byte(found_msg, pos, guess_list, prev_block, target_block):
    """Iterate over each byte to determine the byte value

    Args:
        found_msg - bytearray of the message found so far
        pos - position in the block we are attacking
        guess_list - the dictionary of the possible byte values
        prev_block - the previous block which is XORed against the message
        target_block - the ciphertext block

    Returns:
        the new character + found_msg or None if nothing was found
    """

    # The bytes as if it were a valid PKCS5 pad
    pad = (bytearray((0,)) * (BLOCK_SIZE - pos)) + (bytearray((pos,)) * pos)
    # The plaintext decrypted so far
    plaintext = bytearray((0,)) * (BLOCK_SIZE - len(found_msg)) + found_msg

    xor_msg = xor_bytes(plaintext, prev_block)
    http = urllib3.PoolManager()

    cnt=0
    for guess in guess_list:
        # The single byte guess, padded to be a block to make xor_bytes()
        # Must not overwrite pad, the values are needed for each iteration
        guess_pad = bytearray((0,)) * BLOCK_SIZE
        guess_pad[BLOCK_SIZE - pos] = guess

        # For a padding attack the outcome needs to be the pad bytes at the end of the block.
        # CBC is Plaintext[n] ^ Prev_Block[n] = Intermediate[n]
        # Use XOR cancellation to transform Intermediate[n] -> Pad
        # Prev_Block[n] ^ guess ^ Pad[n]
        # If the guess is correct Prev_Block[n] & Plaintext[n] cancel out leaving only the pad value, which validates
        req = http.request("GET", URL_PREFIX + (xor_bytes(xor_msg, xor_bytes(guess_pad, pad)) + target_block).hex())
        if req.status == 404: # Padding is good
            new_msg = bytearray((guess,)) + found_msg
            return new_msg

    return None



URL_PREFIX = 'http://crypto-class.appspot.com/po?er='
CIPHERTEXT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
BLOCK_SIZE = 16 # AES CBC     


# The viable pad characters excluding 1
padding_chars = []
for i in range(2, BLOCK_SIZE + 1):
    padding_chars.append(i)

# For faster searching try the most probable values first
# In this example we know it is highly probable to be an ASCII English string
# Low probability of random binary or UTF-8 letters
all_chars = []
# [a-z]
for i in range(0x61, 0x7b):
    all_chars.append(i)

# [A-Z]
for i in range(0x41, 0x5b):
    all_chars.append(i)

# punctuation, [0-9]
for i in range(0x20, 0x41):
    all_chars.append(i)

# more punctuation
for i in range(0x5b, 0x61):
    all_chars.append(i)

# lower bytes (including \r\n)
for i in range(0, 0x21):
    all_chars.append(i)

# higher bytes
for i in range(0x7b, 0xff):
    all_chars.append(i)




final_message = bytearray()
blocks = []
idx = 0
while idx < len(CIPHERTEXT):
    blocks.append(bytearray.fromhex(CIPHERTEXT[idx:idx+BLOCK_SIZE*2]))
    idx += BLOCK_SIZE*2

total_blocks = len(blocks) - 1

for b in range(total_blocks,0,-1):
    prev_block = blocks[b - 1]
    block = blocks[b]

    print(f"Attempting block {b}")

    # Calculate the padding
    if b == total_blocks:
        """
        Last byte must be a pad byte with CBC
        Pad bytes are in the range of 1 - BLOCK_SIZE
        A 0x01 will always validate (pad=1, guess=1 == 0x01 ^ 0x01 = 0 = original message)
        It must be the pad if nothing else is
        """
        print(f"Checking pad byte")
        msg = test_a_byte(bytearray(), 1, padding_chars, prev_block, block)
        if len(msg) == 0 or msg == None:
            msg = bytearray((1,))
            msg_idx = 2
        else:
            msg = bytearray((msg[0],)) * msg[0]
            msg_idx = msg[0] + 1

        print(f"{msg_idx - 1} bytes of padding found")
    else:
        msg = bytearray()
        msg_idx = 1

    # Attack the block byte by byte
    for pos in range(msg_idx, BLOCK_SIZE + 1):
        is_found = test_a_byte(msg, pos, all_chars, prev_block, block)
        if is_found:
            msg = is_found
            print(f"msg: {msg}")
        else:
            print(f"Error: Unable to locate byte in position {pos}")
            exit(0)

    if msg:
        final_message = msg + final_message
        print(f"The message is: {final_message}")


# Strip the padding and print out the final message
padding_bytes = final_message[len(final_message)-1]
print(f"Final message:\n{final_message[:len(final_message)-padding_bytes].decode()}")

