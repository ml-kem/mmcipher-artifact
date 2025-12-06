import os
import random
import itertools
from hashlib import sha256
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
import time
# set_random_seed(2025)
# ===================== Kyber-like (p-ary) mmPKE over R_q =====================

# --------------------- Global Parameters ---------------------
# Param1
q = 2**25
N = 16
n = 48
p = 2**8
rr = 2**17
h = 280
sigma = 2**8

# # Param2
# q = 2**41
# N = 8
# n = 128
# p = 2**16
# rr = 2**25
# h = 350
# sigma = 2**16

B_sigma = round(13.4*sigma)
Delta = Integer((q + p//2) // p)

# --------------------- Polynomial Rings ---------------------
RqBase.<t> = PolynomialRing(Zmod(q))
Rq.<X> = RqBase.quotient(t^N + 1)
RZZ.<xZ> = PolynomialRing(ZZ)

# --------------------- Gaussian Sampler ---------------------
gauss_poly_sampler = DiscreteGaussianDistributionPolynomialSampler(RZZ, N, sigma)

def gaussian_poly_in_Rq(q, N):
    """Sample f ∈ R_q from discrete Gaussian (std = sigma)."""
    fZ = gauss_poly_sampler()
    coeffs = [Zmod(q)(fZ[i]) for i in range(N)]
    return Rq(RqBase(coeffs))

def gaussian_poly_in_Rq_pos(q, N):
    """Sample f ∈ R_q from discrete Gaussian (std = sigma)."""
    fZ = gauss_poly_sampler()
    coeffs = [Zmod(q)(abs(fZ[i])) for i in range(N)]
    return Rq(RqBase(coeffs))

def uniform_poly_in_Rq(q, N):
    """Uniform polynomial in R_q."""
    coeffs = [Zmod(q).random_element() for _ in range(N)]
    return Rq(RqBase(coeffs))

def sample_uniform_A_nxn(n, q, N):
    """Uniform n×n matrix A ∈ R_q^{n×n}."""
    return Matrix(Rq, [[uniform_poly_in_Rq(q, N) for _ in range(n)] for __ in range(n)])

def uniform_poly_in_range(r, q, N):
    """Sample polynomial with coeffs ∈ [-r/2, r/2]."""
    if not (0 < r <= q):
        raise ValueError("r must be between 1 and q.")
    coeffs = [Zmod(q)(ZZ.random_element(-r//2, r//2)) for _ in range(N)]
    return Rq(RqBase(coeffs))

# --------------------- Binary Vector Sampler ---------------------
def poly01_from_indices(idx_list, q, N):
    """Build a {0,1}-coefficient polynomial with ones at positions in idx_list."""
    coeffs = [0]*N
    for i in idx_list:
        coeffs[i] = 1
    return Rq(RqBase(coeffs))

def sample_binary_vector_totalHW(vec_len, total_weight, q, N):
    """Sample v ∈ R_q^{vec_len} with total Hamming weight = total_weight."""
    if not (0 <= total_weight <= vec_len * N):
        raise ValueError(f"total_weight must be in [0, {vec_len * N}]")
    base = total_weight // vec_len
    rem  = total_weight % vec_len
    vec = []
    for i in range(vec_len):
        w_i = base + (1 if i < rem else 0)
        idx = random.sample(range(N), w_i) if w_i > 0 else []
        vec.append(poly01_from_indices(idx, q, N))
    return vector(Rq, vec)

# --------------------- Message Sampling ---------------------
def random_p_ary_poly(p, q, N):
    """Sample m ∈ R_q with coeffs ∈ {0,...,p-1}."""
    coeffs = [ZZ.random_element(0, p) for _ in range(N)]
    return Rq(RqBase(coeffs))

# --------------------- Linear Algebra ---------------------
def inner_product(u, v):
    """Compute <u,v> = Σ u_i*v_i in R_q."""
    if len(u) != len(v):
        raise ValueError("Vectors must have the same length.")
    return sum(u[i] * v[i] for i in range(len(u)))

# --------------------- Encoding / Decoding ---------------------
def embed_message(m, Delta, q, N):
    """Embed message m as Δ·m in R_q."""
    pr = m.lift()
    coeffs = [Zmod(q)(int(pr[i]) * Delta) for i in range(N)]
    return Rq(RqBase(coeffs))

def decode_p_ary(poly, p, q, N):
    """p-ary decoding (round(v/(q/p)) mod p)."""
    pr = poly.lift()
    ys = []
    half_q = q // 2
    for i in range(N):
        v = int(pr[i]) % q
        k = Integer((v * p + half_q) // q) % p
        # k = floor(v/rr)
        ys.append(int(k))
    return PolynomialRing(ZZ, 'y')(ys)

def center_lift_poly(poly, q, N):
    """Return a ZZ[x] polynomial whose coefficients are centered in [-q/2, q/2]."""
    pr = poly.lift()
    half = q // 2
    coeffs = []
    for i in range(N):
        v = int(pr[i]) % q
        if v >= half:
            v -= q
        coeffs.append(v)
    return PolynomialRing(ZZ, 'y')(coeffs)

def certer_lift_int(v, q):
    half = q//2
    if v >= half:
        v -= q
    return v

# --------------------- Helpers for consistent display ---------------------
def coeffs_low_to_high(poly, N):
    """Return coefficients [c0, c1, ..., c_{N-1}] for poly = Σ c_i y^i."""
    return [int(poly[i]) for i in range(N)]

def coeffs_high_to_low(poly, N):
    """Return coefficients [c_{N-1}, ..., c1, c0] to match polynomial print order."""
    return list(reversed(coeffs_low_to_high(poly, N)))


import itertools
from hashlib import sha256

def find_m_from_hash_via_bruteforce_complete(
    m_rec_poly,
    target_digest,
    p,
    q,
    N,
    max_twos=2,
    do_full_fallback=True,
    verbose=False,
):
    """
    Recover the true message m_true given m_rec and SHA-256 digest.

    Stage 1: search offsets d_i in {0,1}  (bitmask over all positions)
    Stage 2(k): for k = 1..max_twos:
        choose a subset S (|S|=k) of positions forced to use offset 2,
        and for remaining positions R = [0..N-1] \\ S, search offsets in {0,1} via bitmask.
        (This tries 'very few +2' first.)
    Final fallback (optional): full Cartesian product offsets in {0,1,2}^N.

    Returns:
        (coeff_list, offsets_list) or (None, None).
        - coeff_list is the recovered list m_true[0..N-1] (mod p), low->high
        - offsets_list is the chosen offsets per coordinate in {0,1,2}

    Notes:
        * Stage2(k) complexity is sum_{k<=max_twos} C(N,k)*2^(N-k), typically far smaller than 3^N
        * If do_full_fallback=True and nothing is found, we do the full 3^N search at the end.
    """
    # Precompute basic constants
    mr = [int(m_rec_poly[i]) % p for i in range(N)]
    byte_len = (p.bit_length() + 7) // 8

    def hash_of_coeffs(coeffs):
        """Compute SHA-256 over fixed-width big-endian bytes of coeff list (mod p)."""
        m_bytes = b''.join(int(c % p).to_bytes(byte_len, 'big') for c in coeffs)
        return sha256(m_bytes).hexdigest()

    # ---------------- Stage 1: d_i in {0,1} over all positions (fast) ----------------
    if verbose:
        print("[Stage1] scanning offsets in {0,1}^N ...")
    for mask in range(1 << N):
        # Build candidate coeffs: cand[i] = (mr[i] - (mask_bit_i)) % p
        # NOTE: keep everything in Python ints (no Sage objects) to avoid FLINT issues.
        cand = [(mr[i] - ((mask >> i) & 1)) % p for i in range(N)]
        if hash_of_coeffs(cand) == target_digest:
            offsets = [((mask >> i) & 1) for i in range(N)]
            return cand, offsets

    if verbose:
        print("[Stage1] not found. Entering Stage2 (few +2 positions first) ...")

    # ---------------- Stage 2(k): force exactly k positions to use '+2' ----------------
    # For k from 1 to max_twos:
    #   choose subset S of size k -> those indices always use offset 2
    #   remaining indices R use {0,1} via bitmask
    idx_all = list(range(N))
    for k in range(1, max(0, int(max_twos)) + 1):
        if verbose:
            print(f"[Stage2] trying exactly {k} positions with '+2' ...")
        for S in itertools.combinations(idx_all, k):
            S_set = set(S)
            # Build the list of remaining indices (those not in S)
            R = [i for i in idx_all if i not in S_set]
            # Bitmask over R for {0,1} choices
            for mask in range(1 << len(R)):
                # Compose offsets: 2 on S, and ((mask >> j) & 1) on R[j]
                # Then cand[i] = (mr[i] - offsets[i]) % p
                # Efficiently construct cand in one pass:
                cand = [0]*N
                # Handle S (offset 2)
                for i in S_set:
                    cand[i] = (mr[i] - 2) % p
                # Handle R with bitmask {0,1}
                # R positions are enumerated as R[j] for j in [0..len(R)-1]
                for j, i in enumerate(R):
                    cand[i] = (mr[i] - ((mask >> j) & 1)) % p

                if hash_of_coeffs(cand) == target_digest:
                    # Reconstruct offsets list so caller can see the chosen deltas
                    offsets = [0]*N
                    for i in S_set:
                        offsets[i] = 2
                    for j, i in enumerate(R):
                        offsets[i] = ((mask >> j) & 1)
                    return cand, offsets

    # ---------------- Optional fallback: full {0,1,2}^N Cartesian product ----------------
    if do_full_fallback:
        if verbose:
            print("[Fallback] full search in {0,1,2}^N (this may be slow) ...")
        for offsets in itertools.product((0, 1, 2), repeat=N):
            cand = [(mr[i] - offsets[i]) % p for i in range(N)]
            if hash_of_coeffs(cand) == target_digest:
                return cand, list(offsets)

    if verbose:
        print("CANNOT FIND")
    raise RuntimeError("CANNOT FIND")
    return None, None

# --------------------- PKE Algorithms ---------------------
def setup(q, N, p, n, Delta):
    """Generate system parameters and matrix A."""
    A = sample_uniform_A_nxn(n, q, N)
    params = {'q': q, 'N': N, 'p': p, 'Delta': Delta, 'Rq': Rq, 'A': A, 'n': n}
    return params

def keygen(params):
    """Generate key pair (pk, sk)."""
    A = params['A']; n = params['n']; q = params['q']; N = params['N']
    sk = sample_binary_vector_totalHW(vec_len=n, total_weight=h, q=q, N=N)
    e  = vector(Rq, [gaussian_poly_in_Rq(q, N) for _ in range(n)])
    pk = A.transpose() * sk + e
    return pk, sk

def ATK_keygen(params, special_index = 0):
    """Generate key pair (pk, sk)."""
    A = params['A']; n = params['n']; q = params['q']; N = params['N']

    # 1. Sample binary secret vector s
    sk = sample_binary_vector_totalHW(vec_len=n, total_weight=h, q=q, N=N)

    # 2. Construct special e-vector: only one element has constant coeff = rr


    e_list = []
    for j in range(n):
        coeffs = [0]*N
        if j == special_index:
            coeffs[0] = rr + B_sigma * 2
            # print("p' = ", coeffs[0])
        e_list.append(Rq(RqBase(coeffs)))
    e = vector(Rq, e_list)

    sk_list = []
    for j in range(n):
        coeffs = [0]*N
        if j == special_index:
            coeffs[0] = -1
        sk_list.append(Rq(RqBase(coeffs)))
    sk = vector(Rq, sk_list)

    # 3. Compute public key pk = A^T * sk + e
    pk = A.transpose() * sk + e

    return pk, sk

def enc(params, pk, T=1):
    """Encrypt message m."""
    A = params['A']; n = params['n']; q = params['q']; N = params['N']
    p_loc = params['p']; Delta_loc = params['Delta']
    r = sample_binary_vector_totalHW(vec_len=n, total_weight=h, q=q, N=N)
    e_u = vector(Rq, [gaussian_poly_in_Rq_pos(q, N) for _ in range(n)])
    ct = A * r + e_u
    digest_list = []
    ci_list = []
    m_list = []
    for i in range(T):
        e_i = gaussian_poly_in_Rq_pos(q, N)
        m = random_p_ary_poly(p_loc, q, N)
        m_list.append(m)
        # Auto compute byte length per coefficient for hashing
        byte_len = (p.bit_length() + 7) // 8
        m_bytes = b''.join(int(m.lift()[i]).to_bytes(byte_len, byteorder='big') for i in range(N))
        digest = sha256(m_bytes).hexdigest()
        digest_list.append(digest)
        # print("SHA256(m) =", digest)
        y_i =  uniform_poly_in_range(rr, q, N)
        ci = inner_product(pk[i], r) + e_i + embed_message(m, Delta_loc, q, N) + y_i
        ci_list.append(ci)

    return (ct, ci_list), r, m_list, digest_list, e_u, e_i, y_i

def dec(params, sk, ct_ci):
    """Decrypt ciphertext (ct, ci) and compute exact rounding error (centered)."""
    (ct, ci) = ct_ci
    q = params['q']; N = params['N']; p_loc = params['p']; Delta_loc = params['Delta']
    s = inner_product(ct, sk)
    resid = ci - s
    m_hat = decode_p_ary(resid, p=p_loc, q=q, N=N)
    # Exact rounding error in R_q
    error = resid - embed_message(Rq(RqBase(m_hat)), Delta_loc, q, N)
    # Centered rounding error in ZZ[x] with coeffs in
    error_centered = center_lift_poly(error, q, N)
    return m_hat, error, error_centered

def ATK_dec(params, sk, ct_ci, m_t):
    """Decrypt ciphertext (ct, ci) and compute exact rounding error (centered)."""
    (ct, ci) = ct_ci
    q = params['q']; N = params['N']; p_loc = params['p']; Delta_loc = params['Delta']
    s = inner_product(ct, sk)
    resid = ci - s
    error = resid - embed_message(Rq(RqBase(m_t)), Delta_loc, q, N)
    error_centered = center_lift_poly(error, q, N)
    return error, error_centered

if __name__ == "__main__":

    TRIALS = 2
    total_matches = 0
    rec_fail = 0
    total_attack_time = 0.0

    print("Attack begin:")

    for _ in range(TRIALS):
        params = setup(q, N, p, n, Delta)
        pk_list = []
        ATK_sk_list = []
        for i in range(n):
            pk, sk = ATK_keygen(params, i)
            pk_list.append(pk)
            ATK_sk_list.append(sk)
        pk, sk = keygen(params)
        pk_list.append(pk)
        (ct, ci_list), r, m_true_list, digest_list, e_u, e_i, y_i = enc(params, pk_list, T=n+1)

        # ==================== attack begin  ====================
        attack_start = time.time()

        m_rec_list = []
        for i in range(n):
            m_rec, error, error_centered = dec(params, ATK_sk_list[i], (ct, ci_list[i]))
            m_rec_list.append(m_rec)

        mt_list = []
        mr_list = []

        for j in range(n):
            mt_list.append([int(m_true_list[j].lift()[i]) for i in range(N)])
            mr_list.append([int(m_rec_list[j][i]) for i in range(N)])

        # Try to recover m_true via digest: Stage1 {0,1}, else Stage2 full {0,1,2}
        mt_f_list = []
        rec_r_poly_list = []
        for j in range(n):
            mt_found_list, offsets = find_m_from_hash_via_bruteforce_complete(m_rec_poly=m_rec_list[j], target_digest=digest_list[j], p=p, q=q, N=N, verbose=False)
            mt_f_list.append(mt_found_list)


            error, error_centered = ATK_dec(params, ATK_sk_list[j], (ct, ci_list[j]), mt_found_list)

            ec_hi2lo = coeffs_high_to_low(error_centered, N)

            ec_lo2hi = coeffs_low_to_high(error_centered, N)

            rec_r_list = [0]*N
            for i in range(N):
                if ec_lo2hi[i] >= rr//2 + B_sigma * 2:
                    rec_r_list[i] = 1
            rec_r = Rq(RqBase(rec_r_list))
            rec_r_poly_list.append(rec_r)
            if rec_r != r[j]:
                rec_fail += 1
                print(f"[p={p}, Δ={Delta}] Exact matches over {N} coeffs:", matches, "/", N)
                print("m_true (first 64):", mt[:64])
                print("m_rec  (first 64):", mr[:64])
                print("index: ", j)
                print("rec_r: ", rec_r)
                print("r[0]: ", r[j])
        rec_r_vector = vector(Rq, rec_r_poly_list)
        if r == rec_r_vector:
            print("recover random r succeed!")

        rec_m = Rq(RqBase(decode_p_ary(ci_list[n] - inner_product(pk_list[n], rec_r_vector), p=p, q=q, N=N)))
        if rec_m == m_true_list[n]:
            print("Attack success!")
            print("honest recipient's message: ", m_true_list[n])
            print("attacker recovered message: ", rec_m)

        # ==================== Attack end ====================
        attack_end = time.time()
        attack_time = attack_end - attack_start
        total_attack_time += attack_time
        print(f"[Trial attack time (s)] {attack_time:.6f}")

    print("TRIALS = ", TRIALS)
    print("rec_fail = ", rec_fail)
    avg_time = total_attack_time / TRIALS if TRIALS > 0 else float('nan')
    print(f"[Average attack time over {TRIALS} trials (s)] {avg_time:.6f}")
