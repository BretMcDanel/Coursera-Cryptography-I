#!/usr/bin/env python3
import sys
import os

from Cryptodome.Hash import SHA256

if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit()

file_size = os.path.getsize(sys.argv[1])
block_size = 1024
fp = open(sys.argv[1], 'rb')
last_hash = ''
blocks_left = round((file_size / block_size)+0.5)

# loop through file backwards
while blocks_left > 0:
        blocks_left -= 1
        fp.seek(blocks_left*block_size)
        block = fp.read(block_size)
        hash = SHA256.new()
        hash.update(block)
        if(last_hash):
                hash.update(last_hash)
        last_hash = hash.digest()
fp.close()
print(last_hash.hex())
