rule CRC_8_ATM_poly_0xc1__8_byt_refl_False_ {
  strings:
    $a0 = { 00 c1 43 82 86 47 c5 04 cd 0c 8e 4f 4b 8a 08 c9 5b 9a 18 d9 dd 1c 9e 5f 96 57 d5 14 10 d1 53 92 b6 77 f5 34 30 f1 73 b2 7b ba 38 f9 fd 3c be 7f ed 2c ae 6f 6b aa 28 e9 20 e1 63 a2 a6 67 e5 24 ad 6c ee 2f 2b ea 68 a9 60 a1 23 e2 e6 27 a5 64 f6 37 b5 74 70 b1 33 f2 3b fa 78 b9 bd 7c fe 3f 1b da 58 99 9d 5c de 1f d6 17 95 54 50 91 13 d2 40 81 03 c2 c6 07 85 44 8d 4c ce 0f 0b ca 48 89 9b 5a d8 19 1d dc 5e 9f 56 97 15 d4 d0 11 93 52 c0 01 83 42 46 87 05 c4 0d cc 4e 8f 8b 4a c8 09 2d ec 6e af ab 6a e8 29 e0 21 a3 62 66 a7 25 e4 76 b7 35 f4 f0 31 b3 72 bb 7a f8 39 3d fc 7e bf 36 f7 75 b4 b0 71 f3 32 fb 3a b8 79 7d bc 3e ff 6d ac 2e ef eb 2a a8 69 a0 61 e3 22 26 e7 65 a4 80 41 c3 02 06 c7 45 84 4d 8c 0e cf cb 0a 88 49 db 1a 98 59 5d 9c 1e df 16 d7 55 94 90 51 d3 12 }

  condition:
    $a0
}