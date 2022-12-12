import sys

# def FUNCTION_L(x) : return x ** 2 - 2 * x + 1
def FUNCTION_L(x) : return x*2

def binary_str_to_int(str):
    return int(str, 2)

def int_to_binary_str(num):
    binary = format(num, "b")
    return binary

''' dicrete logarithmic problem '''
def modular_exp(prime, generator, exp):
    print("exp: " + str(exp))
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
    print("Hradcore bit: " + str(hcore_bit) + '\n')
    return str(hcore_bit)

def generate_prg(prime, generator, initial_seed):
    seed_len = len(initial_seed)
    res = ""
    exp = binary_str_to_int(initial_seed)
    for i in range(FUNCTION_L(seed_len)):
        print("Round #" + str(i+1))
        ''' calculating modular exp, discrete log prb '''
        modular_exp_res = modular_exp(prime, generator, exp)
        print("modular_exp: " + str(modular_exp_res))
        ''' calculating hardcore bit '''
        hcore_bit = hardcore_bit(modular_exp_res, prime)
        ''' adding the hardcore bit in the resultant string '''
        res = res + hcore_bit
        exp = modular_exp_res
    return res

def main() :
    # 5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587, 719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823, 1907
    prime = 1907
    # generator = 31
    generator = 987
    prime = int(input("Enter the prime number(The prime should be such that p-1/2 should also be prime. Sophie Germain Prime)(1907, ..): "))
    generator = int(input("Enter the generator(Primitive root for the prime)(987, 31, ..): "))
    initial_seed = input("Enter the seed in binary: ")
    print("Initial Seed length: " + str(len(initial_seed)))
    print("(PRG length = 2 * initial seed length): " + str(2 * len(initial_seed)) + "\n")
    prg = generate_prg(prime, generator, initial_seed)
    # print("The initial seed in binary is: " + str(initial_seed))
    # print("The initial seed in decimal is: " + str(int(initial_seed, 2)))
    print("The generated provably secure PRG in binary is: " + str(prg) + "\n")
    # print("The generated provably secure PRG in decimal is: " + str(int(prg, 2)))

if __name__ == '__main__':
    main()
