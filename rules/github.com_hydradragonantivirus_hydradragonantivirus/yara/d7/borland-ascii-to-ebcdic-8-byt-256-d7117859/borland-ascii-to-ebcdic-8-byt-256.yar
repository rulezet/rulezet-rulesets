rule Borland_ascii_to_ebcdic__8_byt_256_ {
  strings:
    $a0 = { 00 01 02 03 37 2d 2e 2f 16 05 25 0b 0c 0d 0e 0f 10 11 12 13 3c 3d 32 26 18 19 3f 27 1c 1d 1e 1f 40 4f 7f 7b 5b 6c 50 7d 4d 5d 5c 4e 6b 60 4b 61 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 7a 5e 4c 7e 6e 6f 7c c1 c2 c3 c4 c5 c6 c7 c8 c9 d1 d2 d3 d4 d5 d6 d7 d8 d9 e2 e3 e4 e5 e6 e7 e8 e9 4a e0 5a 5f 6d 79 81 82 83 84 85 86 87 88 89 91 92 93 94 95 96 97 98 99 a2 a3 a4 a5 a6 a7 a8 a9 c0 6a d0 a1 07 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f 3f ff }

  condition:
    $a0
}