rule CRC_8_Dallas_Maxim_poly_0x31__8_byt_refl_False_ {
  strings:
    $a0 = { 00 31 62 53 c4 f5 a6 97 b9 88 db ea 7d 4c 1f 2e 43 72 21 10 87 b6 e5 d4 fa cb 98 a9 3e 0f 5c 6d 86 b7 e4 d5 42 73 20 11 3f 0e 5d 6c fb ca 99 a8 c5 f4 a7 96 01 30 63 52 7c 4d 1e 2f b8 89 da eb 3d 0c 5f 6e f9 c8 9b aa 84 b5 e6 d7 40 71 22 13 7e 4f 1c 2d ba 8b d8 e9 c7 f6 a5 94 03 32 61 50 bb 8a d9 e8 7f 4e 1d 2c 02 33 60 51 c6 f7 a4 95 f8 c9 9a ab 3c 0d 5e 6f 41 70 23 12 85 b4 e7 d6 7a 4b 18 29 be 8f dc ed c3 f2 a1 90 07 36 65 54 39 08 5b 6a fd cc 9f ae 80 b1 e2 d3 44 75 26 17 fc cd 9e af 38 09 5a 6b 45 74 27 16 81 b0 e3 d2 bf 8e dd ec 7b 4a 19 28 06 37 64 55 c2 f3 a0 91 47 76 25 14 83 b2 e1 d0 fe cf 9c ad 3a 0b 58 69 04 35 66 57 c0 f1 a2 93 bd 8c df ee 79 48 1b 2a c1 f0 a3 92 05 34 67 56 78 49 1a 2b bc 8d de ef 82 b3 e0 d1 46 77 24 15 3b 0a 59 68 ff ce 9d ac }

  condition:
    $a0
}