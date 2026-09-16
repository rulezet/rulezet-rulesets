rule Frog_seed__8_byt_256_ {
  strings:
    $a0 = { 71 15 e8 12 71 5c 3f 9d 7c c1 a6 c5 7e 38 e5 e5 9c a2 36 11 e6 59 bd 57 a9 00 51 cc 08 46 cb e1 a0 3b a7 bd 64 9d 54 0b 07 82 1d 33 20 2d 87 ed 8b 21 11 dd 18 32 59 4a 15 cd bf f2 54 35 03 e6 e7 76 0f 0f 6b 04 15 22 03 9c 39 42 5d ff bf 03 55 87 cd c8 b9 cc 34 25 23 18 44 b9 c9 0a e0 ea 07 78 c9 73 d8 67 39 ff 5d 6e 2a f9 44 0e 1d 37 80 54 25 98 dd 89 27 0b fc 32 90 23 b2 be 2b a2 67 f9 6d 08 eb 21 9e 6f fc cd a9 36 0a 14 dd c9 b2 e0 59 b8 b6 41 c9 0a 3c 06 bf ae 4f 62 1a a0 fc 33 3f 4f 06 66 7b ad 31 03 6e e9 5a 9e e4 d2 d1 ed 1e 5f 1c b3 cc dc 48 a3 4d a6 c0 62 a5 19 91 a2 5b d4 29 e6 6e 06 6b bb 7f 26 52 62 1e 43 e1 50 d0 86 3c fa 99 57 94 3c 42 a5 48 1d a5 52 d3 cf 00 b1 ce 0d 06 0e 5c f8 3c c9 84 5f 23 d7 76 b1 79 b4 1b 53 83 1a 27 2e 0c 00 00 00 00 00 }

  condition:
    $a0
}