rule libavcodec_wp_log2_table__8_byt_256_ {
  strings:
    $a0 = { 00 01 03 04 06 07 09 0a 0b 0d 0e 10 11 12 14 15 16 18 19 1a 1c 1d 1e 20 21 22 24 25 26 28 29 2a 2c 2d 2e 2f 31 32 33 34 36 37 38 39 3b 3c 3d 3e 3f 41 42 43 44 45 47 48 49 4a 4b 4d 4e 4f 50 51 52 54 55 56 57 58 59 5a 5c 5d 5e 5f 60 61 62 63 64 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a9 aa ab ac ad ae af b0 b1 b2 b2 b3 b4 b5 b6 b7 b8 b9 b9 ba bb bc bd be bf c0 c0 c1 c2 c3 c4 c5 c6 c6 c7 c8 c9 ca cb cb cc cd ce cf d0 d0 d1 d2 d3 d4 d4 d5 d6 d7 d8 d8 d9 da db dc dc dd de df e0 e0 e1 e2 e3 e4 e4 e5 e6 e7 e7 e8 e9 ea ea eb ec ed ee ee ef f0 f1 f1 f2 f3 f4 f4 f5 f6 f7 f7 f8 f9 f9 fa fb fc fc fd fe ff ff }

  condition:
    $a0
}