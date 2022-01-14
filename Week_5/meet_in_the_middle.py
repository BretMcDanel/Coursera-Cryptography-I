#!/usr/bin/env python3
"""We want to find:
       h/g**x1 = (g**B)**x0 in Z_p
"""

import gmpy2

# Values are provided in the assignment instructions
B = gmpy2.mpz(2**20)

p = gmpy2.mpz('134078079299425970995740249982058461274793658205923933'
              '77723561443721764030073546976801874298166903427690031'
              '858186486050853753882811946569946433649006084171')

g = gmpy2.mpz('11717829880366207009516117596335367088558084999998952205'
              '59997945906392949973658374667057217647146031292859482967'
              '5428279466566527115212748467589894601965568')

h = gmpy2.mpz('323947510405045044356526437872806578864909752095244'
              '952783479245297198197614329255807385693795855318053'
              '2878928001494706097394108577585732452307673444020333')



"""Build a hash table of the left hand side of all possible values
   h/g**x1 in Z_p
"""
print("Building hash table")
HASH_TABLE = {}

for x1 in range(B):
    # g**x1 % p
    g_power_x1 = gmpy2.powmod(g, x1, p)

    # modular multiplicative inverse
    inv = gmpy2.mul(h, gmpy2.invert(g_power_x1, p))

    # modulo p
    HASH_TABLE[gmpy2.f_mod(inv, p)] = x1

print("Table is completed")


"""Solve the right hand side
   (g**B)**x0
"""

# g**B % p
g_power_b = gmpy2.powmod(g, B, p)
for x0 in range(B):
    # g_power_b**x0 % p
    z = gmpy2.powmod(g_power_b, x0, p)
    if z in HASH_TABLE:
        # We found the entry
        x1 = HASH_TABLE[z]
        break

# There is no error checking, but supplied values always works
x = (x0*B+x1)%(p-1)
print(f"x = {x}")
