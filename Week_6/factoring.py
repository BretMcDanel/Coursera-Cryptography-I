#!/usr/bin/env python3

import gmpy2

N_1 = gmpy2.mpz('17976931348623159077293051907890247336179769789423065727343008115'
                '77326758055056206869853794492129829595855013875371640157101398586'
                '47833778606925583497541085196591615128057575940752635007475935288'
                '71082364994994077189561705436114947486504671101510156394068052754'
                '0071584560878577663743040086340742855278549092581')


N_2 = gmpy2.mpz('6484558428080716696628242653467722787263437207069762630604390703787'
                '9730861808111646271401527606141756919558732184025452065542490671989'
                '2428844841839353281972988531310511738648965962582821502504990264452'
                '1008852816733037111422964210278402893076574586452336833570778346897'
                '15838646088239640236866252211790085787877')

N_3 = gmpy2.mpz('72006226374735042527956443552558373833808445147399984182665305798191'
                '63556901883377904234086641876639384851752649940178970835240791356868'
                '77441155132015188279331812309091996246361896836573643119174094961348'
                '52463970788523879939683923036467667022162701835329944324119217381272'
                '9276147530748597302192751375739387929')

N_4 = gmpy2.mpz('22096451867410381776306561134883418017410069787892831071731839143676'
               '13560012053800428232965047350942434394621975151225646583996794288946'
               '07645420405815647489880137348641204523252293201764879166664029975091'
               '88729971690526083222067771600019329260870009579993724077458967773697'
               '817571267229951148662959627934791540')


def challenge_1(N):
    """Factoring Challenge 1

       N is a product of two primes p and q where |p-q| < 2N**(1/4).
       Find the smaller of the two factors

       Assignment instructions explain the math (highlights below):
       A = ceil(sqrt(N))
       x = sqrt(A**2-n)
       find the factors p and q of N since p = A - x and q = A + x
    """
    A = gmpy2.isqrt(N) + 1
    x = gmpy2.isqrt(A**2 - N)
    p = A - x
    return p



def challenge_2(N):
    """Factoring Challenge 2

       N is a product of two primes p and q where |p - q| < 2**11 N**(1/4)
       Find the smaller of the two factors

       Similar to Challenge 1 but scanning is required
       Assignment instruction hint: 
          A - sqrt(N) < 2**20 so try scanning for A from sqrt(N) upwards, until you succeed
    """

    sqrt_n = gmpy2.isqrt(N)
    A = sqrt_n + 1

    while A < (gmpy2.mpz(2**20) + sqrt_n):
        x = gmpy2.isqrt(A**2 - N)
        p = A - x
        q = A + x
        if N == (p * q):
            return p
        A += 1

def challenge_3(N):
    """Factoring Challenge 3

       N is a product of two primes p and q where |3p - 2q| < N**(1/4)
       Find the smaller of the two factors

       Assignment instruction hint:
          First show that sqrt(6N) is close to ( (3p+2q)/2 ) and then adapt the method in challenge #1 to factor N

       This one is a little different because (3p+2q)/2 is not evenly divisible by 2
       A = (6p+4q)/2
       which means A > sqrt(24N)
       and x = sqrt(A**2 - 24N)
    """

    A = gmpy2.isqrt(24 * N) + 1
    x = gmpy2.isqrt(A**2 - (24 * N))
    p = gmpy2.mpz((A - x) / 6)
    return p
    

def challenge_4(ciphertext, N):
    """Factoring Challenge 4
    
       Use the factorization from Challenge 1 to decrypt the challenge ciphertext (a decimal integer)
       Assignment instruction hint:
          Recall that the factorization of N enables you to compute phi_N from which you can obtain the RSA decryption exponent.
    """
    e = 65537

    # Copy paste from challenge 1
    A = gmpy2.isqrt(N) + 1
    x = gmpy2.isqrt(A**2 - N)
    p = A - x
    q = A + x

    # Euler's totient function
    # phi_N = (p - 1) * (q - 1)
    phi_N = (p - 1) * (q - 1)

    # RSA decryption
    d = gmpy2.invert(e, phi_N)
    pt_num = gmpy2.powmod(ciphertext, d, N)
    # convert to bytes (128 bytes/1024 bit long)
    plaintext = int.to_bytes(int(pt_num), 128, 'big')

    # Remove padding
    for idx, byte_value in enumerate(plaintext):
        if byte_value == 0x00:
            plaintext = plaintext[idx+1:]
            break

    return plaintext.decode()

print(f"Challenge 1:\n{challenge_1(N_1)}\n")
print(f"Challenge 2:\n{challenge_2(N_2)}\n")
print(f"Challenge 3:\n{challenge_3(N_3)}\n")
print(f"Challenge 4:\n{challenge_4(N_4, N_1)}\n")
