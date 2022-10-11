from sage.all import *
from pwn import *
from Crypto.Util.number import bytes_to_long

def chunk(input_data, size):
    return [input_data[i:i+size] for i in range(0, len(input_data), size)]

def long_to_bytes(data):
    data = int(data)
    data = hex(data).rstrip('L').lstrip('0x')
    if len(data) % 2 == 1:
        data = '0' + data
    return bytes(bytearray(int(c, 16) for c in chunk(data, 2)))

def gcd(a, b): 
    while b:
        a, b = b, a % b
    return a.monic()

def franklin(n, pad1, pad2, c1, c2, e):
    R.<X> = PolynomialRing(Zmod(n))
    f1 = (X + pad1)^e - c1
    f2 = (X + pad2)^e - c2
    return -gcd(f1, f2).coefficients()[0]

def main():
    r = remote("oneflagpadding.challs.srdnlen.it", 15006)
    enc_flag = int(r.recvuntil(">").split()[4].decode("utf-8"))
    length = 10
    sent_string = length*b'A'
    r.sendline(sent_string)
    text = r.recvline()
    e = 7
    r.recvline()
    n = int(r.recvline().split()[1].decode("utf-8"))
    enc_message = int(r.recvline().split()[1].decode("utf-8"))
    r.close()

    for i in range(100, 5000):
        pad1 = 0
        pad2 = bytes_to_long(sent_string)*(2**i)
        result = franklin(n, pad1, pad2, enc_flag, enc_message, e)
        if b'srd' in long_to_bytes(result):
            print(result)

main()