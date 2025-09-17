# Secret Message

> _I've encrypted (RSA PKCS#1 v1.5) a secret message for each of my closest 10,000 friends. Too bad you're not one of them!_

Attached: [`certs.tar.gz`](./Files/certs.tar.gz)

## 1. Exploration

Extracting the archive revealed 10,000 X.509 certificates in PEM format (`.pem`). No ciphertexts were provided separately, so the first puzzle was: **where is the ciphertext?**

X.509 certificates typically contain:

- Metadata: subject, issuer, validity period.
- The public key.
- Extensions: standard OIDs such as `2.5.29.19` (Basic Constraints) or `2.5.29.17` (Subject Alternative Name).

Extensions can also include custom OIDs, defined under an organization's namespace. These are usually opaque to parsers, just blobs of bytes.

While parsing the certificates (with Python's `cryptography` library), I noticed an unusual extension:

```
OID = 1.3.3.7.102.108.97.103
```

Look closer: the tail of this OID is `102 108 97 103` that's ASCII for `f l a g`. **The ciphertext is hidden inside a custom "flag" extension.**

The raw value of this extension was a base64-encoded blob. This was almost certainly our encrypted message.

## 2. Plan of Attack

We now had:

- **Public keys** (`n`, `e`) from each certificate.
- **Ciphertexts** (from the custom OID).

To decrypt, we'd need the private key. But RSA's security depends on $n = p \\times q$ being hard to factor.

With so many certificates with relatively standard exponents and moduli, the most obvious path to investigate was to look for shared factors between the moduli. We can do that by checking the Greatest Common Denominator between every pair of moduli.

If two different RSA moduli share a prime, say:

$$
\\begin{aligned}
n_1 &= p \\times q_1 \\
n_2 &= p \\times q_2
\\end{aligned}
$$

then $\\gcd(n_1, n_2) = p$ reveals a factor of both.

## 3. First Attempt: Brute-force GCD

The simplest method: compute `gcd` of every pair of moduli.

```python
for i, n1 in enumerate(ns):
    for n2 in ns[i + 1 :]:
        p = math.gcd(n1, n2)
        if p > 1:
            print("Found shared factor!", p)
            print("n1:", n1)
            print("n2:", n2)
             exit()
print("FAIL")
```

I was rewarded with:

```
Found shared factor! 9908281327815141963413376029567044979515248355396908644903471943944940946438491825140712566229275682077974232087516228997445939363287787310069504715201113
n1: 114286715613296817234867239503156391401582037423435274581682040938707455422192079738646525319813005664458420653830787815127819863854358397446871483640386456160037443280494543353038377282656188339432605321550993392296376414099114151073983751926794406829119137976520346338872605208496773006328959775798235531717
n2: 94012853651602509551025770298152833087542907826350017727673637167925240468517202247831220382748913468672940723301368906452788144367248504225945458853248311247305415378971973117485194417801707656981585940253487356502145612330495142305332427732874809434615910589537581034871274551766745600738871615184148202001
```

## 4. RSA Math Refresher

Once we have $p$, reconstructing the private key is straightforward:

$$
\\begin{aligned}
q &= n \\div p \\
\\phi &= (p - 1) \\times (q - 1) \\
d &= e^{-1} \\mod \\phi \\
m &= C^d \\mod n
\\end{aligned}
$$

Then apply PKCS#1 v1.5 unpadding to recover the plaintext.

I used python-cryptography to handle PKCS#1 v1.5 unpadding. My final code looks like this:

```python
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import math
from base64 import b64decode


TARGET_OID = "1.3.3.7.102.108.97.103"  # "flag" in OID form
CERTS_DIR = "certs"  # Path to the folder with all the certs

ns = []
cts = []


def extract_ciphertext(cert):
    for ext in cert.extensions:
        oid = getattr(ext.oid, "dotted_string", "")
        if oid == TARGET_OID:
            val = getattr(ext.value, "value", None)
            if isinstance(val, (bytes, bytearray)):
                return b64decode(bytes(val))


def make_private_key(n, e, p):
    q = n // p
    if p > q:
        p, q = q, p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    priv = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    ).private_key(default_backend())
    return priv


for filename in os.listdir(CERTS_DIR):
    if not filename.endswith(".pem"):
        continue

    path = os.path.join(CERTS_DIR, filename)

    with open(path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        n = numbers.n
        # e = numbers.e # 65537
        ns.append(n)
        cts.append(extract_ciphertext(cert))

priv = None
for i, n1 in enumerate(ns):
    for n2 in ns[i + 1 :]:
        p = math.gcd(n1, n2)
        if p > 1:
            print("DONE")
            print("n1:", n1)
            print("n2:", n2)
            priv = make_private_key(n1, 65537, p)
            print("FLAG:", priv.decrypt(cts[i], padding.PKCS1v15()))
            break
    if priv:
        break
else:
    print("FAIL")
    exit()
```

```
DONE
n1: 114286715613296817234867239503156391401582037423435274581682040938707455422192079738646525319813005664458420653830787815127819863854358397446871483640386456160037443280494543353038377282656188339432605321550993392296376414099114151073983751926794406829119137976520346338872605208496773006328959775798235531717
n2: 94012853651602509551025770298152833087542907826350017727673637167925240468517202247831220382748913468672940723301368906452788144367248504225945458853248311247305415378971973117485194417801707656981585940253487356502145612330495142305332427732874809434615910589537581034871274551766745600738871615184148202001
FLAG: b'SVUSCG{Sh4r3d_Pr1m3s_L34k_S3cr3ts!}'
```

## 5. Optimized Solution: Batch GCD

As an aside, instead of $O(n^2)$ comparisons, we can use the **batch GCD** algorithm with product/remainder trees. This reduces complexity to $O(n \\log n)$ and finds all shared factors efficiently.

```python
import os
import binascii
from pathlib import Path
from math import gcd

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from base64 import b64decode

CERTS_DIR = "certs"

TARGET_OID = "1.3.3.7.102.108.97.103"  # "flag" in OID form


class Entry:
    __slots__ = ("name", "n", "e", "c", "key_bytes")

    def __init__(self, name, n, e, c, key_bytes):
        self.name = name
        self.n = n
        self.e = e
        self.c = c
        self.key_bytes = key_bytes


def load_cert(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(data, default_backend())
    return cert


def extract_ciphertext(cert):
    for ext in cert.extensions:
        oid = getattr(ext.oid, "dotted_string", "")
        val = getattr(ext.value, "value", None)
        if isinstance(val, (bytes, bytearray)):
            if oid == TARGET_OID:
                return b64decode(bytes(val))


def parse_all(certs_dir):
    entries = []
    for fname in sorted(os.listdir(certs_dir)):
        if not fname.lower().endswith(".pem"):
            continue
        path = os.path.join(certs_dir, fname)
        cert = load_cert(path)
        pub = cert.public_key()
        if not isinstance(pub, rsa.RSAPublicKey):
            continue
        numbers = pub.public_numbers()
        n = numbers.n
        e = numbers.e
        c = extract_ciphertext(cert)
        if c is None:
            # no ciphertext sized blob found, skip
            continue
        entries.append(Entry(fname, n, e, c, key_bytes))
    return entries


# ---------- Batch GCD via product/remainder trees ----------
def build_product_tree(nums):
    """Return list of levels; level[0] = nums, level[-1] = root product(s)."""
    levels = [nums]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt = []
        for i in range(0, len(prev), 2):
            if i + 1 < len(prev):
                nxt.append(prev[i] * prev[i + 1])
            else:
                nxt.append(prev[i])
        levels.append(nxt)
    return levels


def build_remainder_tree(levels):
    """Compute for each leaf N_i the product of all other N_j modulo N_i without division."""
    # Start from the top level with a single remainder = 1
    remainders = [None] * len(levels[0])
    top = levels[-1]
    # Each node at top has remainder 1
    rem_level = [1] * len(top)

    # Walk downwards
    for depth in range(len(levels) - 2, -1, -1):
        curr = levels[depth]
        parent = levels[depth + 1]
        new_rem = [None] * len(curr)
        for i in range(len(curr)):
            parent_idx = i // 2
            sib_idx = i ^ 1  # sibling within the pair
            # product outside this node = rem at parent * (product of sibling subtree, if sibling exists)
            outside = rem_level[parent_idx]
            if (i % 2 == 0) and (i + 1 < len(curr)):
                sib_prod = curr[i + 1]
                outside = (outside * sib_prod) % curr[i]
            elif i % 2 == 1:
                sib_prod = curr[i - 1]
                outside = (outside * sib_prod) % curr[i]
            else:
                # no sibling (odd count), just reduce the parent's remainder mod this node's product
                outside = outside % curr[i]
            new_rem[i] = outside
        rem_level = new_rem

    # rem_level now holds M_i = product(all j != i) mod N_i for leaves
    return rem_level


def batch_gcd(entries):
    Ns = [e.n for e in entries]
    levels = build_product_tree(Ns)
    Mi = build_remainder_tree(levels)  # M_i = \prod_{j!=i} N_j (mod N_i)

    factors = {}
    for i, N in enumerate(Ns):
        g = gcd(N, Mi[i])
        if 1 < g < N:
            factors[i] = g  # g is a non-trivial factor (shared prime)
    return factors  # mapping index -> shared prime


# ---------- Key reconstruction & decrypt ----------
def make_private_key(n, e, p):
    q = n // p
    if p > q:
        p, q = q, p
    phi = (p - 1) * (q - 1)
    # modular inverse: Python 3.8+ supports pow(e,-1,phi)
    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    priv = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n),
    ).private_key(default_backend())
    return priv


def try_decrypt(entry, p):
    key = make_private_key(entry.n, entry.e, p)
    pt = key.decrypt(entry.c, padding.PKCS1v15())
    return pt


def main():
    entries = parse_all(CERTS_DIR)
    if not entries:
        print("No RSA certs with a ciphertext-like extension found.")
        return
    print(f"Loaded {len(entries)} certs with ciphertexts.")

    factors = batch_gcd(entries)
    if not factors:
        print("No shared prime factors found via batch GCD. (Unlucky? Try all 10k.)")
        return

    print(
        f"Found {len(factors)} vulnerable keys (shared primes). Attempting decrypt..."
    )
    printed_any = False
    for idx, p in factors.items():
        ent = entries[idx]
        try:
            pt = try_decrypt(ent, p)
            # Print a nice summary once
            if not printed_any:
                print("\n=== First recovered plaintext ===")
                try:
                    print(pt.decode("utf-8", "replace"))
                except Exception:
                    print("hex:", binascii.hexlify(pt).decode())
                printed_any = True
            # Show which file worked
            print(f"(Recovered from: {ent.name})")
        except Exception as ex:
            # If something odd with padding, skip
            pass

    if not printed_any:
        print(
            "Got shared primes but decryption failed (unexpected). Check padding or ciphertext extraction logic."
        )


if __name__ == "__main__":
    main()
```

```
Loaded 10000 certs with ciphertexts.
Found 2 vulnerable keys (shared primes). Attempting decrypt...

=== First recovered plaintext ===
SVUSCG{Sh4r3d_Pr1m3s_L34k_S3cr3ts!}
(Recovered from: frosty_wilbur-9769.pem)
(Recovered from: inspiring_joliot-8713.pem)
```

## 6. Takeaways

- **Key insight:** The challenge authors hid ciphertext in a sneaky custom OID extension.
- **Weakness exploited:** Shared primes between RSA moduli. This is a known real-world vulnerability when systems reuse primes due to poor randomness.
- **Technique learned:** Brute-force pairwise GCD works, but batch GCD is vastly more efficient for large keysets.

This was a nice blend of PKI internals + RSA number theory + algorithm design.
