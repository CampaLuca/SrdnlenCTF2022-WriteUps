from pwn import *
from factordb.factordb import FactorDB
from random import randint
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
import re
import logging

logging.disable()

e = 13
Ns = []
CTs = []

rem = remote("easyrsa.challs.srdnlen.it", 9000)

for _ in range(15):
    rem.recvuntil(b"x*y:")
    n = int(rem.recvline().strip())

    f = FactorDB(n)
    f.connect()
    p, q = f.get_factor_list()

    phi = (p-1) * (q-1)
    k = randint(2**128, 2**130)
    r = phi * randint(2**128, 2**130)

    rem.sendline(str(k).encode())
    rem.sendline(str(r).encode())

    rem.recvuntil(b"N:")
    Ns.append(int(rem.recvline().strip()))
    rem.recvuntil(b"CT:")
    CTs.append(int(rem.recvline().strip()))

    # print(Ns, CTs)

plain_root = crt(Ns, CTs)[0]
plain, isroot = iroot(plain_root, 13)

assert isroot is True

print(f"flag: {re.sub('poba', '', long_to_bytes(plain).decode())}")
# trovo m ossia la flag






