# Resources
# Sir's Lecture and slide
# Teextbook Introduction_to_Modern_Cryptography page 277

def modular_exp(prime, generator, exp):
    # print("exp: " + str(exp))
    return pow(generator, exp, prime)


''' in case of discrete log, hardcore bit is the MSB of the binary str '''
# https://crypto.stanford.edu/pbc/notes/crypto/hardcore.html
# https://en.wikipedia.org/wiki/Blum%E2%80%93Micali_algorithm
def hardcore_bit(num, prime):
    hcore_bit = 0
    if(num <= (prime-1)/2):
        hcore_bit = 1
    else:
        hcore_bit = 0
    # print("Hradcore bit: " + str(hcore_bit) + '\n')
    return str(hcore_bit)


def generate_binary_random_string_of_n_bits(prime, generator, length):
    initial_seed = input("Input a seed in binary for PRG: ")
    # print("Input in PRG: " + str(initial_seed))
    res = ""
    exp = int(initial_seed, 2)
    for i in range(length):
        ''' calculating modular exp, discrete log prb '''
        modular_exp_res = modular_exp(prime, generator, exp)
        # print("modular_exp: " + str(modular_exp_res))
        ''' calculating hardcore bit '''
        hcore_bit = hardcore_bit(modular_exp_res, prime)
        ''' adding the hardcore bit in the resultant string '''
        res = res + hcore_bit
        exp = modular_exp_res
    return res

def calculate_dlp_hash(prime, generator, h, x1, x2):
    # x1 and x2 should be in range of 0 and prime-1
    x1_mod_p = x1 % prime
    x2_mod_p = x2 % prime
    print("x1_mod_p: " + str(x1_mod_p) + ", x2_mod_p: " + str(x2_mod_p))
    res = pow(generator, x1_mod_p, prime) * pow(h, x2_mod_p, prime) % prime
    res_binary = format(res, "b")
    # return res_binary

    # If the length of res is less than no of bits in prime, append 0's at beginning to resize it
    prime_bin_len = len(format(prime, "b"))
    res = res_binary.zfill(prime_bin_len)
    return res


# https: // www.youtube.com/watch?v = kQ6t7NoxSHo
# https: // www.youtube.com/watch?v = aHg9RF4Huq8
def main():
    print("*************************************************************************************************************")
    print("The logic is as follows")
    print("The length of prime numebr(in binary) should be equal to x1, x2(in binary)(The data which will be provided)")
    print("So ideally we should know data length from user and then choose a prime of that length")
    print("In case of merkle damgard transform, the two datas(msg and vector) will be of same length say n")
    print("So, then we should choose a prime number which is of length n in binary")
    print("Then choose primitive root or generator g")
    print("Then choose h randomly b/w 1 to prime")
    print("Then take input of data x1 and x2, in range 0 to (prime-1)")
    print("Or we can choose prime beforehand, tell user that our prime is of n bits")
    print("So, data will be divided into blocks of size n(length of prime)")
    print("So, if your data is of less than n bits in any block, pad 0's at end")
    print("*************************************************************************************************************")
    prime = 1907
    generator = 987
    prime = int(input(
        "\nEnter the prime number(The prime should be such that p-1/2 should also be prime. Sophie Germain Prime)(1907): "))
    generator = int(
        input("Enter the generator(Primitive root for the prime)(987, 31, ..): "))

    prime_bin = format(prime, "b")

    # h = random.randrange(1, prime)

    h_bin = generate_binary_random_string_of_n_bits(prime, generator, len(prime_bin))
    h = int(h_bin, 2) % prime + 1

    # temp_exp = random.randrange(1, prime)
    # h = pow(generator, temp_exp, prime)

    print("\nRandomly selected h from 1 to prime: " + str(h))

    x1 = input("\nEnter a number b/w 0 to " + str(prime-1) + "(" + prime_bin + ")" + " in binary(keep number of bits(" + str(len(prime_bin)) + ") same as prime for length halving): ")
    x2 = input("\nEnter a number b/w 0 to " + str(prime-1) + "(" + prime_bin + ")" + " in binary(keep number of bits(" + str(len(prime_bin)) + ") same as prime for length halving): ")


    x1_int = int(x1, 2)
    x2_int = int(x2, 2)

    print("x1: " + str(x1_int))
    print("x2: " + str(x2_int))

    print("Length of (x1+x2): " + str(len(x1) + len(x2)))
    hash_res = calculate_dlp_hash(prime, generator, h, x1_int, x2_int)
    print("Hash Res: " + str(hash_res))
    print("Hash Res length: " + str(len(hash_res)))


if __name__ == '__main__':
    main()
