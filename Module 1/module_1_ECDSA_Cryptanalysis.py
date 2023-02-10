import math
import random
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Euclidean algorithm for gcd computation
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

# Modular inversion computation
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

def bits_to_int(list_of_bits):
    
    val = 0
    for i in list_of_bits:
        val = val * 2
        if(i == 1):
            val = val + 1
    return val


def diagonalmatrix(val, dim):

    i = 0
    matrix = []

    while i < dim:
        j = 0
        row = []
        while j < dim:
            if i == j:
                row.append(val)
            else:
                row.append(0)
            j += 1

        matrix.append(row)
        i += 1

    return matrix

def check_x(x, Q):
    """ Given a guess for the secret key x and a public key Q = [x]P,
        checks if the guess is correct.

        :params x:  secret key, as an int
        :params Q:  public key, as a tuple of two ints (Q_x, Q_y)
    """
    x = int(x)
    if x <= 0:
        return False
    Q_x, Q_y = Q
    sk = ec.derive_private_key(x, ec.SECP256R1())
    pk = sk.public_key()
    xP = pk.public_numbers()
    return xP.x == Q_x and xP.y == Q_y

def recover_x_known_nonce(k, h, r, s, q):
    # Implement the "known nonce" cryptanalytic attack on ECDSA
    # The function is given the nonce k, (h, r, s) and the base point order q
    # The function should compute and return the secret signing key x
    x = mod_inv(r, q) * (k*s - h) % q
    return x

def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA
    # The function is given the (hashed-message, signature) pairs (h_1, r_1, s_1) and (h_2, r_2, s_2) generated using the same nonce
    # The function should compute and return the secret signing key x
    x = (h_1*s_2 - h_2*s_1) * mod_inv(r_2*s_1 - r_1*s_2, q) % q
    return x


def MSB_to_Padded_Int(N, L, list_k_MSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L most significant bits of the nonce k 
    # The function should return a.2^{N - L} + 2^{N -L -1}
    a = bits_to_int(list_k_MSB)
    return a * 2**(N-L) + 2**(N-L - 1)

def LSB_to_Int(list_k_LSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L least significant bits of the nonce k 
    # The function should return a
    a = bits_to_int(list_k_LSB)
    return a

def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u) computed as described in the lectures
    # In the case of EC-Schnorr, r may be set to h
    if algorithm == "ecdsa":

        if givenbits == "msbs":

            t = r * mod_inv(s, q) % q
            
            z = h * mod_inv(s, q) % q
            u = (MSB_to_Padded_Int(N, L, list_k_MSB) - z) % q

        if givenbits == "lsbs":

            #T/2^L * x = 1/2^L * (a - z) + e
            t = r * mod_inv(s, q) * mod_inv(2**L, q) % q

            z = h * mod_inv(s, q) % q
            u = mod_inv(2**L, q) * (LSB_to_Int(list_k_MSB) - z) % q


    if algorithm == "ecschnorr":

        if givenbits == "msbs":

            #hx = A + e - s
            t = h % q
            u = (MSB_to_Padded_Int(N, L, list_k_MSB) - s) % q

        if givenbits == "lsbs":

            #hx = A + Be - s
            t = h * mod_inv(2**L, q) % q
            u = mod_inv(2**L, q) * (LSB_to_Int(list_k_MSB) - s) % q

    return t, u


def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement a function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return a list of t values and a list of u values computed as described in the lectures
    # Hint: Use the function you implemented above to set up the t and u values for each instance
    # In the case of EC-Schnorr, list_r may be set to list_h
    list_t = []
    list_u = []

    for i in range(num_Samples):

        t, u = setup_hnp_single_sample(N, L, listoflists_k_MSB[i], list_h[i], list_r[i], list_s[i], q, givenbits, algorithm)
        list_t.append(t)
        list_u.append(u)


    return list_t, list_u

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # Implement a function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function should return the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    # NOTE: The basis matrix B and the CVP target vector u should be scaled appropriately. Refer lecture slides and lab sheet for more details 
    
    #Q1: -

    #Q2: from exercise session, fpylll does not support non integral entries => need to multiply by appropriate scalar

    #Q3: multiply by 2^(L+1) (both the matrix and the search vector)
    c = 2**(L+1)

    B_CVP = diagonalmatrix(c*q, num_Samples+1)
    B_CVP[len(B_CVP) - 1] = list(map(lambda x : x * c, list_t)) + [1]

    u_CVP = list(map(lambda x : x * c, list_u)) + [0]

    return B_CVP, u_CVP


def cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and converts it into an instance of the shortest vector problem (SVP)
    # Your function should use the Kannan embedding technique in the lecture slides
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should use the Kannan embedding technique to output the corresponding SVP basis matrix B' of apropriate dimensions.
    # The SVP basis matrix B' should again be implemented as a nested list
    
    for i in range(len(cvp_basis_B)):
        cvp_basis_B[i].append(0)

    #Q6: M should be equal to half Gaussian Heuristic (but it works only for n >= 45 and random lattices)

    # 1. after experimenting: M must be corrected by a certain correction factor (the only problem with heuristic is L = 8)
    # 
    # 2. Lab hint: see how M relates to distance => with M bigger than heuristic also other L fail, try to reduce M 
    #
    # 3. correction factor = 1/10 (all work but L = 8) => correction factor = 1/100 IT WORKS
    #
    # 4. with 1/(2*num_Samples) we get factor 1/120 for 60 samples => it still works (but maybe better since more scalable)

    #Q7: no need 
    
    q = cvp_basis_B[0][0]
    
    correction_factor = 1/(2*num_Samples)
    M = int(1/2 * q**(num_Samples/(num_Samples+1)) * math.sqrt(num_Samples+1)/math.sqrt(2 * math.pi * math.e) * correction_factor)
    
    cvp_basis_B.append(cvp_list_u + [M])

    return cvp_basis_B



def solve_cvp(cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should output the solution vector v (to be implemented as a list)
    # NOTE: The basis matrix B should be processed appropriately before being passes to the fpylll CVP-solver. See lab sheet for more details
    
    #Q4-5: perform LLL reduction
    cvp_basis_B = IntegerMatrix.from_matrix(cvp_basis_B)
    cvp_basis_B = LLL.reduction(cvp_basis_B)

    closest_vector = list(CVP.closest_vector(cvp_basis_B, cvp_list_u))

    return closest_vector

def solve_svp(svp_basis_B):
    # Implement a function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function should output a list of candidate vectors that may contain x as a coefficient
    # NOTE: Recall from the lecture and also from the exercise session that for ECDSA cryptanalysis based on partial nonces, you might want
    #       your function to include in the list of candidate vectors the *second* shortest vector (or even a later one). 
    # If required, figure out how to get the in-built SVP-solver functions from the fpylll library to return the second (or later) shortest vector
    
     
    # Q8: after research online: LLL reduction algorithm solves approximately SVP within a certain factor
    # => first basis vector is approximate solution to SVP 
    # BUT possibly (f M) is not actually the shortest vector 
    # Lab hint: (f M) is most probably the second largest vector
    # after (not detailed, but apparently it works so who cares) research online + lab hint: row vectors after LLL should be in order 
    # => second basis vector of reduced lattice is the second shortest
 

    svp_basis_B = IntegerMatrix.from_matrix(svp_basis_B)
    svp_basis_B = LLL.reduction(svp_basis_B)

    return list(svp_basis_B)

def recover_x_partial_nonce_CVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    v_List = solve_cvp(cvp_basis_B, cvp_list_u)
    # The function should recover the secret signing key x from the output of the CVP solver and return it
    #already scaled
    
    x = v_List[len(v_List) - 1] % q

    return x

def recover_x_partial_nonce_SVP(Q, N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits="msbs", algorithm="ecdsa"):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA and EC-Schnorr using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q, givenbits, algorithm)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    list_of_f_List = solve_svp(svp_basis_B)
    # The function should recover the secret signing key x from the output of the SVP solver and return it
    
    #v = w - f
    #compute v[len(v) - 1] = w[len(w) - 1] - f[len(f) - 1]

    f_prime = list_of_f_List[1] #this is actually f' = (f, M) not f
    
    x = (cvp_list_u[len(cvp_list_u) - 1] - f_prime[len(f_prime) - 2]) % q

    return x



# testing code: do not modify

from module_1_ECDSA_Cryptanalysis_tests import run_tests

run_tests(recover_x_known_nonce,
    recover_x_repeated_nonce,
    recover_x_partial_nonce_CVP,
    recover_x_partial_nonce_SVP
)
