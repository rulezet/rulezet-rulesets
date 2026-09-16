rule Whirlpool_sbox__8_byt_256_ {
  strings:
    $a0 = { 68 d0 eb 2b 48 9d 6a e4 e3 a3 56 81 7d f1 85 9e 2c 8e 78 ca 17 a9 61 d5 5d 0b 8c 3c 77 51 22 42 3f 54 41 80 cc 86 b3 18 2e 57 06 62 f4 36 d1 6b 1b 65 75 10 da 49 26 f9 cb 66 e7 ba ae 50 52 ab 05 f0 0d 73 3b 04 20 fe dd f5 b4 5f 0a b5 c0 a0 71 a5 2d 60 72 93 39 08 83 21 5c 87 b1 e0 00 c3 12 91 8a 02 1c e6 45 c2 c4 fd bf 44 a1 4c 33 c5 84 23 7c b0 25 15 35 69 ff 94 4d 70 a2 af cd d6 6c b7 f8 09 f3 67 a4 ea ec b6 d4 d2 14 1e e1 24 38 c6 db 4b 7a 3a de 5e df 95 fc aa d7 ce 07 0f 3d 58 9a 98 9c f2 a7 11 7e 8b 43 03 e2 dc e5 b2 4e c7 6d e9 27 40 d8 37 92 8f 01 1d 53 3e 59 c1 4f 32 16 fa 74 fb 63 9f 34 1a 2a 5a 8d c9 cf f6 90 28 88 9b 31 0e bd 4a e8 96 a6 0c c8 79 bc be ef 6e 46 97 5b ed 19 d9 ac 99 a8 29 64 1f ad 55 13 bb f7 6f b9 47 2f ee b8 7b 89 30 d3 7f 76 82 }

  condition:
    $a0
}