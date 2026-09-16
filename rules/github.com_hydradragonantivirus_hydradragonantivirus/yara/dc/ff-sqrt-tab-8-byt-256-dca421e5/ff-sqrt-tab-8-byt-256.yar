rule ff_sqrt_tab__8_byt_256_ {
  strings:
    $a0 = { 00 10 17 1c 20 24 28 2b 2e 30 33 36 38 3a 3c 3e 40 42 44 46 48 4a 4c 4d 4f 50 52 54 55 57 58 5a 5b 5c 5e 5f 60 62 63 64 66 67 68 69 6b 6c 6d 6e 6f 70 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 90 91 92 93 94 95 96 97 97 98 99 9a 9b 9c 9c 9d 9e 9f a0 a0 a1 a2 a3 a4 a4 a5 a6 a7 a8 a8 a9 aa ab ab ac ad ae ae af b0 b0 b1 b2 b3 b3 b4 b5 b6 b6 b7 b8 b8 b9 ba ba bb bc bc bd be be bf c0 c0 c1 c2 c2 c3 c4 c4 c5 c6 c6 c7 c8 c8 c9 ca ca cb cc cc cd cd ce cf cf d0 d0 d1 d2 d2 d3 d4 d4 d5 d5 d6 d7 d7 d8 d8 d9 da da db db dc dc dd de de df df e0 e0 e1 e2 e2 e3 e3 e4 e4 e5 e6 e6 e7 e7 e8 e8 e9 e9 ea eb eb ec ec ed ed ee ee ef ef f0 f0 f1 f2 f2 f3 f3 f4 f4 f5 f5 f6 f6 f7 f7 f8 f8 f9 f9 fa fa fb fb fc fc fd fd fe fe ff ff ff }

  condition:
    $a0
}