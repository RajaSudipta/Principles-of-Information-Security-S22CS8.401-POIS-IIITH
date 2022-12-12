# Resources
# Sir's Lecture and slide
# Teextbook Introduction_to_Modern_Cryptography page 119(basic-cbc), 121(secure-cbc #2)

def FUNCTION_L(x): return x*2


def binary_str_to_int(str):
    return int(str, 2)


def int_to_binary_str(num):
    binary = format(num, "b")
    return binary


''' dicrete logarithmic problem '''
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


def generate_prg(prime, generator, initial_seed):
    # print("Input in PRG: " + str(initial_seed))
    seed_len = len(initial_seed)
    res = ""
    exp = binary_str_to_int(initial_seed)
    for i in range(FUNCTION_L(seed_len)):
        ''' calculating modular exp, discrete log prb '''
        modular_exp_res = modular_exp(prime, generator, exp)
        # print("modular_exp: " + str(modular_exp_res))
        ''' calculating hardcore bit '''
        hcore_bit = hardcore_bit(modular_exp_res, prime)
        ''' adding the hardcore bit in the resultant string '''
        res = res + hcore_bit
        exp = modular_exp_res
    return res


''' Fk:{0, 1}^n --> {0, 1}^n, input length = output length '''
''' Fk(x1x2x3...xn) = Gxn(...(Gx2(Gx1(k)))) '''
''' Fk(011) = G1(G1(G0(k))) '''
''' function f will take a key k and data(seed) in binary '''
''' then, it will call prg and generate data, if ith bit of seed is 0, left half of key, if 1, right half of the key  '''


def generate_prf(prime, generator, initial_seed, key):
    res = key
    for i in range(len(initial_seed)):
        res = generate_prg(prime, generator, res)
        # print("Output of PRG: " + str(res))
        if(initial_seed[i] == '0'):
            # print(str(i) + "th bit of seed " +
            #       str(initial_seed) + " is " + initial_seed[i] + ". So, choosing the first half of PRG as exp " + res[0:len(res)//2])
            res = res[0:len(res)//2]
        else:
            # print(str(i) + "th bit of seed " +
            #       str(initial_seed) + " is " + initial_seed[i] + ". So, choosing the second half of PRG as exp " + res[len(res)//2:])
            res = res[len(res)//2:]
    return res


_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}


def xor(x, y):
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])


# def rand_key(length):

#     # Variable to store the string
#     key1 = ""

#     # Loop to find the string of desired length
#     for i in range(length):

#         # randint function to generate 0, 1 randomly and converting the result into str
#         temp = str(random.randint(0, 1))

#         # Concatenation the random 0, 1 to the final result
#         key1 += temp

#     return(key1)


def generate_binary_random_string_of_n_bits(prime, generator, initial_seed, length):
    print("Input in PRG: " + str(initial_seed))
    res = ""
    exp = binary_str_to_int(initial_seed)
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


def encode_into_binary_string_of_given_length(num, length):
    binary = format(num, "b")
    # padding leading zeros upto length
    res = binary.zfill(length)
    return res


_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}

def xor(x, y):
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])

def generate_cbc_mac(prime, generator, key, data, block_size):
    unpadded_data_len = len(data)
    # If the data length is not multiple of block size, pad zeros
    if(len(data) % block_size != 0):
        no_of_zeros_to_be_padded = (
            block_size * (len(data)//block_size + 1)) - len(data)
        for i in range(no_of_zeros_to_be_padded):
            data += '0'
        print("\nData after zero padding: " + data)
    
    split_string = [data[i:i+block_size]
                    for i in range(0, len(data), block_size)]
    print("\nAfter dividing the data into blocks of size: " + str(block_size) + " => ")
    print(split_string)
    no_of_blocks = len(split_string)

    # Step-1: encode data length upto block_size, PRF Fk(data_len)
    unpadded_data_len_encoded = encode_into_binary_string_of_given_length(unpadded_data_len, block_size)
    print("\nunpadded_data_len_encoded: " + str(unpadded_data_len_encoded))
    initial_prf = generate_prf(prime, generator, unpadded_data_len_encoded, key)
    t = initial_prf
    print("Initial PRF(t0): " + str(initial_prf))

    # Now, in each stage calculate Fk(ti xor mi)
    for i in range(no_of_blocks):
        print("\nRound #" + str(i+1))
        mi = split_string[i]
        print("ti: " + str(t) + ", mi: " + str(mi))
        t_xor_mi = xor(t, mi)
        print("t_xor_mi: " + t_xor_mi)
        prf_res = generate_prf(prime, generator, t_xor_mi, key)
        t = prf_res
        print("prf_res: " + str(prf_res))
    
    # print("CBC-MAC: " + str(t))
    return t


def main():
    # 5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587, 719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823, 1907
    prime = 1907
    # generator = 31
    generator = 987
    prime = int(input(
        "Enter the prime number(The prime should be such that p-1/2 should also be prime. Sophie Germain Prime)(1907, ..): "))
    generator = int(
        input("Enter the generator(Primitive root for the prime)(987, 31, ..): "))

    ''' length of the key and seed avaialble in following link '''
    ''' https://www.ccs.neu.edu/home/wichs/class/crypto-fall15/lecture9.pdf '''
    # out_len = int(input("Enter the length of prf you want: "))
    # key = input("Enter the key in binary of length " + str(out_len) + ": ")
    # initial_seed = input(
    #     "Enter the data(initial seed) in binary (preferably) of length " + str(out_len) + ": ")
    # prf = generate_prf(prime, generator, initial_seed, str(key))
    # print("\nThe data(initial seed) in binary is: " + str(initial_seed))
    # # print("The data(initial seed) in decimal is: " + str(int(initial_seed, 2)))
    # print("The key entered: " + str(key))
    # print("The generated provably secure PRF in binary is: " + str(prf))
    # print("The generated provably secure PRF in decimal is: " + str(int(prf, 2)))

    key = input("Enter the key in binary: ")
    print("The length of key is: " + str(len(key)))
    key_len = len(key)

    data = input("Enter data in binary(preferably of length multiple of " + str(key_len) + "): ")

    print("Block size will be same as key size(" + str(key_len) + ")")
    block_size = key_len

    cbc_mac_tag = generate_cbc_mac(prime, generator, key, data, block_size)
    print("\nCBC MAC TAG: " + cbc_mac_tag + "\n")


if __name__ == '__main__':
    main()
