from pwn import *
import time 
from ctypes import CDLL

libc = CDLL('libc.so.6')

p = process('./mr_unlucky')
# p = remote('52.59.124.14', 5021)

heroes = [
    "Anti-Mage", "Axe", "Bane", "Bloodseeker", "Crystal Maiden",
    "Drow Ranger", "Earthshaker", "Juggernaut", "Mirana", "Morphling",
    "Phantom Assassin", "Pudge", "Shadow Fiend", "Sniper", "Storm Spirit",
    "Sven", "Tiny", "Vengeful Spirit", "Windranger", "Zeus"
]

current_time = libc.time(0)
libc.srand(current_time)

for i in range(50):
    hero = libc.rand() % 20
    guesshero = heroes[hero]

    print(b'Guessing...')

    p.recvuntil(b'Guess the Dota 2 hero (case sensitive!!!): ')
    p.sendline(guesshero.encode())


p.interactive()


