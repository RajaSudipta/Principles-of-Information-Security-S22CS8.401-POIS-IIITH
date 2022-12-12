import sys

# def FUNCTION_L(x) : return x ** 2 - 2 * x + 1


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
    print("Input in PRG: " + str(initial_seed))
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
        print("\nRound #" + str(i+1))
        res = generate_prg(prime, generator, res)
        print("Output of PRG: " + str(res))
        if(initial_seed[i] == '0'):
            print(str(i) + "th bit of data " +
                  str(initial_seed) + " is " + initial_seed[i] + ". So, choosing the first half of PRG as exp " + res[0:len(res)//2])
            res = res[0:len(res)//2]
        else:
            print(str(i) + "th bit of data " +
                  str(initial_seed) + " is " + initial_seed[i] + ". So, choosing the second half of PRG as exp " + res[len(res)//2:])
            res = res[len(res)//2:]
    return res


def main():
    # 5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587, 719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823, 1907
    prime = 1907
    # generator = 31
    generator = 987
    prime = int(input(
        "Enter the prime number(The prime should be such that p-1/2 should also be prime. Sophie Germain Prime)(1907, ..): "))
    generator = int(
        input("Enter the generator(Primitive root for the prime)(987, 31, ..): "))
    # key_len = int(input("Enter length of the key: "))
    # key = secrets.randbits(key_len)
    # ''' Convert the key to binary '''
    # key = int_to_binary_str(key)
    # print("key: " + str(key))
    ''' length of the key and seed avaialble in following link '''
    ''' https://www.ccs.neu.edu/home/wichs/class/crypto-fall15/lecture9.pdf '''
    out_len = int(input("Enter the length of prf you want: "))
    key = input("Enter the key in binary of length " + str(out_len) + ": ")
    # initial_seed = input(
    #     "Enter the data(initial seed) in binary (preferably) of length " + str(out_len) + ": ")
    initial_seed = input("Enter the data(initial seed) in binary: ")
    prf = generate_prf(prime, generator, initial_seed, str(key))
    print("\nThe data(initial seed) in binary is: " + str(initial_seed))
    # print("The data(initial seed) in decimal is: " + str(int(initial_seed, 2)))
    print("The key entered: " + str(key))
    print("The generated provably secure PRF in binary is: " + str(prf) + "\n")
    # print("The generated provably secure PRF in decimal is: " + str(int(prf, 2)))


if __name__ == '__main__':
    main()
