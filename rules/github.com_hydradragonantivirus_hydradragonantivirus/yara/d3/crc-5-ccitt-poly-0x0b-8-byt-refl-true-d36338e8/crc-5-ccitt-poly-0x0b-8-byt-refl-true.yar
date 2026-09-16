rule CRC_5_CCITT_poly_0x0b__8_byt_refl_True_ {
  strings:
    $a0 = { 00 e5 6b 8e d6 33 bd 58 0d e8 66 83 db 3e b0 55 1a ff 71 94 cc 29 a7 42 17 f2 7c 99 c1 24 aa 4f 34 d1 5f ba e2 07 89 6c 39 dc 52 b7 ef 0a 84 61 2e cb 45 a0 f8 1d 93 76 23 c6 48 ad f5 10 9e 7b 68 8d 03 e6 be 5b d5 30 65 80 0e eb b3 56 d8 3d 72 97 19 fc a4 41 cf 2a 7f 9a 14 f1 a9 4c c2 27 5c b9 37 d2 8a 6f e1 04 51 b4 3a df 87 62 ec 09 46 a3 2d c8 90 75 fb 1e 4b ae 20 c5 9d 78 f6 13 d0 35 bb 5e 06 e3 6d 88 dd 38 b6 53 0b ee 60 85 ca 2f a1 44 1c f9 77 92 c7 22 ac 49 11 f4 7a 9f e4 01 8f 6a 32 d7 59 bc e9 0c 82 67 3f da 54 b1 fe 1b 95 70 28 cd 43 a6 f3 16 98 7d 25 c0 4e ab b8 5d d3 36 6e 8b 05 e0 b5 50 de 3b 63 86 08 ed a2 47 c9 2c 74 91 1f fa af 4a c4 21 79 9c 12 f7 8c 69 e7 02 5a bf 31 d4 81 64 ea 0f 57 b2 3c d9 96 73 fd 18 40 a5 2b ce 9b 7e f0 15 4d a8 26 c3 }

  condition:
    $a0
}