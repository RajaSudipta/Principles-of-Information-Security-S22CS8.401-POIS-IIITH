# Resources
# Sir's Lecture and slide
# Teextbook Introduction_to_Modern_Cryptography page 136, 277

IPAD = "00110110"  # 36
OPAD = "01011100"  # 5C


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


def encode_into_binary_string_of_given_length(num, length):
    binary = format(num, "b")
    # padding leading zeros upto length
    res = binary.zfill(length)
    return res


def calculate_dlp_hash(prime, generator, h, x1, x2):
    # x1_int = int(x1, 2)
    # x2_int = int(x2, 2)
    # res = pow(generator, x1_int, prime) * pow(h, x2_int, prime) % prime
    # res_binary = format(res, "b")
    # return res_binary

    x1_int = int(x1, 2)
    x2_int = int(x2, 2)
    # x1 and x2 should be in range of 0 and prime-1
    x1_mod_p = x1_int % prime
    x2_mod_p = x2_int % prime
    print("x1_mod_p: " + str(format(x1_mod_p, "b")) +
          ", x2_mod_p: " + str(format(x2_mod_p, "b")))
    res = pow(generator, x1_mod_p, prime) * pow(h, x2_mod_p, prime) % prime
    res_binary = format(res, "b")
    # return res_binary

    # If the length of res is less than no of bits in prime, append 0's at beginning to resize it
    prime_bin_len = len(format(prime, "b"))
    res = res_binary.zfill(prime_bin_len)
    return res


def merkle_damgard_transform(p, g, h, p_bin, l, data):
    unpadded_data_len = len(data)
    # first check whether the data len is multiple of l or not, pad zeros if necessary
    if(len(data) % l != 0):
        no_of_zeros_to_be_padded = (l * (len(data)//l + 1)) - len(data)
        for i in range(no_of_zeros_to_be_padded):
            data += '0'
        print("\nData after zero padding: " + data)

    # Splitting the data into boxes of length l
    split_string = [data[i:i+l]
                    for i in range(0, len(data), l)]
    print(split_string)

    # Define initial vector z0 = 0^l
    txt = ""
    z0 = txt.zfill(l)
    print("\nThe initial vector is: " + z0)

    print("Now, this zi and xi will act as (x1, x2) in the dlp based hash function")

    for i in range(len(split_string)):
        print("\nRound #" + str(i+1))
        print("Vector z" + str(i) + ": " + str(z0))
        print("x" + str(i+1) + ": " + split_string[i])
        print("Concatenated data inseted into dlp hash: " +
              str(z0) + "||" + split_string[i])
        z0 = calculate_dlp_hash(p, g, h, z0, split_string[i])
        print("Obtained hash for this round: " + str(z0))

    # Encode the length of the data in a string of length l
    # data_len_encoded = encode_into_binary_string_of_given_length(len(data), l)
    data_len_encoded = encode_into_binary_string_of_given_length(
        unpadded_data_len, l)

    # At the end, hash (z0||length of msg)
    print("\nLast Round")
    print("hash (z0||length of msg)")
    print("z: " + str(z0))
    print("L: " + str(data_len_encoded))
    print("Concatenated data inseted into dlp hash: " +
          str(z0) + "||" + str(data_len_encoded))
    final_hash_res = calculate_dlp_hash(p, g, h, z0, data_len_encoded)

    print("Obtained hash for this round: " + final_hash_res)

    return final_hash_res


_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}


def xor(x, y):
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])


def encode_into_binary_string_of_given_length(num, length):
    binary = format(num, "b")
    # padding leading zeros upto length
    res = binary.zfill(length)
    return res


def construct_hmac(p, g, h, p_bin, k, data, IV):
    l = len(p_bin)
    unpadded_data_len = len(data)
    # make the ipad and opad up to the length of l if not
    modified_IPAD = IPAD
    modified_OPAD = OPAD
    if(l != len(IPAD)):
        for i in range(l-len(IPAD)):
            modified_IPAD += IPAD[i % len(IPAD)]
    if(l != len(OPAD)):
        for i in range(l-len(OPAD)):
            modified_OPAD += OPAD[i % len(OPAD)]

    print("\nModified IPAD: " + str(modified_IPAD))
    print("Modified OPAD: " + str(modified_OPAD))

    # Step1: calculate k xor ipad
    k_xor_ipad = xor(k, modified_IPAD)

    print("k_xor_ipad: " + str(k_xor_ipad) + "\n")

    # first check whether the data len is multiple of l or not, pad zeros if necessary
    if(len(data) % l != 0):
        no_of_zeros_to_be_padded = (l * (len(data)//l + 1)) - len(data)
        for i in range(no_of_zeros_to_be_padded):
            data += '0'
        print("Data after zero padding: " + data)

    # Now, split data into blocks of size n = prime_bin_len
    l = len(p_bin)
    split_string = [data[i:i+l]for i in range(0, len(data), l)]
    print(split_string)

    no_of_blocks = len(split_string)

    print("\nRound #0")
    x1 = k_xor_ipad
    x2 = IV
    print("x1: " + str(x1) + ", x2: " + str(x2))
    x2 = calculate_dlp_hash(p, g, h, x1, x2)
    print("Hash Res: " + str(x2))

    for i in range(no_of_blocks):
        print("\nRound #" + str(i+1))
        x1 = split_string[i]
        print("x1: " + str(x1) + ", x2: " + str(x2))
        dlp_hash_res = calculate_dlp_hash(p, g, h, x1, x2)
        x2 = dlp_hash_res
        print("Hash Res: " + str(dlp_hash_res))

    print("\nNow, x1 will be encoded length of data")
    # Encode the length of the data in a string of length l
    # data_len_encoded = encode_into_binary_string_of_given_length(len(data), l)
    data_len_encoded = encode_into_binary_string_of_given_length(
        unpadded_data_len, l)
    print("Round #" + str(i+1))
    x1 = data_len_encoded
    print("x1: " + str(x1) + ", x2: " + str(x2))
    dlp_hash_res = calculate_dlp_hash(p, g, h, x1, x2)
    print("Hash Res: " + str(dlp_hash_res))

    print("\nNow, hashing b/w k_xor_opad and IV")
    print("key: " + str(k))
    print("Modified OPAD: " + str(modified_OPAD))
    k_xor_opad = xor(k, modified_OPAD)
    print("Round #" + str(i+2))
    x1 = k_xor_opad
    x2 = IV
    print("x1: " + str(x1) + ", x2: " + str(x2))
    dlp_hash_res_2 = calculate_dlp_hash(p, g, h, x1, x2)
    print("Hash Res: " + str(dlp_hash_res_2))

    print("\nLast Round")
    x1 = dlp_hash_res
    x2 = dlp_hash_res_2
    print("x1: " + str(x1) + ", x2: " + str(x2))
    hmac_tag = calculate_dlp_hash(p, g, h, x1, x2)
    # print("HMAC Res: " + str(hmac_tag))

    return hmac_tag


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
    prime_bin_len = len(prime_bin)

    # h = random.randrange(1, prime)

    h_bin = generate_binary_random_string_of_n_bits(
        prime, generator, len(prime_bin))
    h = int(h_bin, 2) % prime + 1

    # temp_exp = random.randrange(1, prime)
    # h = pow(generator, temp_exp, prime)

    print("\nRandomly selected h from 1 to prime: " + str(h))

    # x1 = input("Enter a number b/w 0 to " + str(prime-1) + "(" + format(prime-1, "b") +
    #            ")" + " in binary(keep number of bits same as prime for length halving) : ")
    # x2 = input("Enter a number b/w 0 to " + str(prime-1) + "(" + format(prime-1, "b") +
    #            ")" + " in binary(keep number of bits same as prime for length halving) : ")

    # x1_int = int(x1, 2)
    # x2_int = int(x2, 2)

    # print("x1: " + str(x1_int))
    # print("x2: " + str(x2_int))

    # print("Length of (x1+x2): " + str(len(x1) + len(x2)))
    # hash_res = calculate_hash(prime, generator, h, x1_int, x2_int)
    # print("Hash Res: " + str(hash_res))
    # print("Hash Res length: " + str(len(hash_res)))

    print("\nPrime choosen: " + str(prime) + ", in binary: " +
          str(prime_bin) + ", length = " + str(prime_bin_len))

    key = input("\nEnter key k in binary of length " +
                str(prime_bin_len) + " for xor with ipad and opad: ")

    # if key length is shorter, pad zeros in left
    if(len(key) < prime_bin_len):
        key.zfill(prime_bin_len)
    elif(len(key) > prime_bin_len):
        key = key[0:prime_bin_len]

    IV = input("\nEnter initialization vector of lebgth " +
               str(prime_bin_len) + ": ")

    data = input("\nEnter data in binary of any length: ")

    hmac_tag = construct_hmac(prime, generator, h, prime_bin, key, data, IV)

    print("\nHMAC TAG: " + str(hmac_tag) + "\n")


if __name__ == '__main__':
    main()
