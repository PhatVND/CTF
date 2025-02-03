# Nullcon Goa HackIM 2025 CTF - MR UNLUCKY

Tiếp tục nào, đọc tên thì có vẻ nó liên quan đến gì đó may rủi (I hate GAMBLING)

```
File:     /home/kali/CTF/nullcon/unlucky/mr_unlucky
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

À okay, bật gần như là full bảo mật, cùng nhau decompile xem chương trình làm gì nhé.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int i; // [rsp+8h] [rbp-38h]
  int v6; // [rsp+Ch] [rbp-34h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("I have always been unlucky. I can't even win a single game of dota2 :(");
  puts("however, I heard that this tool can lift the curse that I have!");
  puts("YET I CAN'T BEAT IT'S CHALLENGE. Can you help me guess the names?");
  v3 = time(0LL);
  srand(v3);
  sleep(3u);
  puts(
    "Welcome to dota2 hero guesser! Your task is to guess the right hero each time to win the challenge and claim the aegis!");
  for ( i = 0; i <= 49; ++i )
  {
    v6 = rand() % 20;
    printf("Guess the Dota 2 hero (case sensitive!!!): ");
    fgets(s, 30, stdin);
    s[strcspn(s, "\n")] = 0;
    if ( strcmp(s, (&heroes)[v6]) )
    {
      printf("Wrong guess! The correct hero was %s.\n", (&heroes)[v6]);
      exit(0);
    }
    printf("%s was right! moving on to the next guess...\n", s);
  }
  puts("Wow you are one lucky person! fine, here is your aegis (roshan will not be happy about this!)");
  print_flag("flag.txt");
  return 0;
}
```

Thứ mà mình để ý đầu tiên là srand với `time` là 0, đây là kiểu của Bad Seed attack. Phân tích chương trình nhé, người viết ra chương trình này có 1 thành tích rất đáng kể trong tựa
game Dota 2: với chuỗi thắng là 0 (giống bản thân mình trong tựa game LMHT...), nên anh ta đã cho chúng ta giúp anh ta bằng cách đoán đúng tên các `Heroes` trong Dota 2 50 lần. Với những tên vị tướng đó
xuất hiện hoàn toàn ngẫu nhiên. Thật ra không phải ngẫu nhiên đâu, thoạt nhìn là như thế thôi, nhưng trong chương trình C này có lỗ hổng đó là dùng seed để random là thời gian hiện tại, `srand = time(0)`. Nên
ta gần như có thể biết được con số sẽ được generate là bao nhiêu rồi. Giờ ta chỉ cần đoán trúng 50 lần thì sẽ in ra `flag`. Dưới đây là danh sách heroes hiển thị trong decompiler của mình

```
i.data:0000000000004020                                                                       ; "Anti-Mage"
.data:0000000000004028 12 20 00 00 00 00 00 00       dq offset aAxe                          ; "Axe"
.data:0000000000004030 16 20 00 00 00 00 00 00       dq offset aBane                         ; "Bane"
.data:0000000000004038 1B 20 00 00 00 00 00 00       dq offset aBloodseeker                  ; "Bloodseeker"
.data:0000000000004040 27 20 00 00 00 00 00 00       dq offset aCrystalMaiden                ; "Crystal Maiden"
.data:0000000000004048 36 20 00 00 00 00 00 00       dq offset aDrowRanger                   ; "Drow Ranger"
.data:0000000000004050 42 20 00 00 00 00 00 00       dq offset aEarthshaker                  ; "Earthshaker"
.data:0000000000004058 4E 20 00 00 00 00 00 00       dq offset aJuggernaut                   ; "Juggernaut"
.data:0000000000004060 59 20 00 00 00 00 00 00       dq offset aMirana                       ; "Mirana"
.data:0000000000004068 60 20 00 00 00 00 00 00       dq offset aMorphling                    ; "Morphling"
.data:0000000000004070 6A 20 00 00 00 00 00 00       dq offset aPhantomAssassi               ; "Phantom Assassin"
.data:0000000000004078 7B 20 00 00 00 00 00 00       dq offset aPudge                        ; "Pudge"
.data:0000000000004080 81 20 00 00 00 00 00 00       dq offset aShadowFiend                  ; "Shadow Fiend"
.data:0000000000004088 8E 20 00 00 00 00 00 00       dq offset aSniper                       ; "Sniper"
.data:0000000000004090 95 20 00 00 00 00 00 00       dq offset aStormSpirit                  ; "Storm Spirit"
.data:0000000000004098 A2 20 00 00 00 00 00 00       dq offset aSven                         ; "Sven"
.data:00000000000040A0 A7 20 00 00 00 00 00 00       dq offset aTiny                         ; "Tiny"
.data:00000000000040A8 AC 20 00 00 00 00 00 00       dq offset aVengefulSpirit               ; "Vengeful Spirit"
.data:00000000000040B0 BC 20 00 00 00 00 00 00       dq offset aWindranger                   ; "Windranger"
.data:00000000000040B8 C7 20 00 00 00 00 00 00       dq offset aZeus                         ; "Zeus"
```

# EXPLOITATION

```
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
```

`from ctypes import CDLL`, dòng này cho phép chương trình Python của ta có thể liên kết với dynamic linking libraries trong C và C++. Và từ đó ta gọi ra các hàm random
cũng như generate theo time hiện tại.

```
libc = CDLL('libc.so.6')
current_time = libc.time(0)
libc.srand(current_time)
```

Ta lấy thời gian hiện tại làm `seed`, sau đó ta sẽ dùng nó để generate ngẫu nhiên. Và bây giờ chỉ cần 1 tí reverse code để thấy rằng chương trình C ở trên sẽ lấy con số
ngẫu nhiên đó `%` 20, và dùng đó làm index trong các danh sách `Heroes`. Ta chỉ cần gửi các `Heroes` này thì sẽ xong thôi.

```
Anti-Mage was right! moving on to the next guess...
Wow you are one lucky person! fine, here is your aegis (roshan will not be happy about this!)
Aegis: nullconCTF{fake_flag}[*] Got EOF while reading in interactive
```
