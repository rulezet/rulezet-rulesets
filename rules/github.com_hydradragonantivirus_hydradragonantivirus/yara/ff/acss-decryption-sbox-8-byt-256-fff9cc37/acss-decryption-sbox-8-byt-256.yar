rule ACSS_decryption_sbox__8_byt_256_ {
  strings:
    $a0 = { 33 73 3b 26 63 23 6b 76 3e 7e 36 2b 6e 2e 66 7b d3 93 db 06 43 03 4b 96 de 9e d6 0b 4e 0e 46 9b 57 17 5f 82 c7 87 cf 12 5a 1a 52 8f ca 8a c2 1f d9 99 d1 00 49 09 41 90 d8 98 d0 01 48 08 40 91 3d 7d 35 24 6d 2d 65 74 3c 7c 34 25 6c 2c 64 75 dd 9d d5 04 4d 0d 45 94 dc 9c d4 05 4c 0c 44 95 59 19 51 80 c9 89 c1 10 58 18 50 81 c8 88 c0 11 d7 97 df 02 47 07 4f 92 da 9a d2 0f 4a 0a 42 9f 53 13 5b 86 c3 83 cb 16 5e 1e 56 8b ce 8e c6 1b b3 f3 bb a6 e3 a3 eb f6 be fe b6 ab ee ae e6 fb 37 77 3f 22 67 27 6f 72 3a 7a 32 2f 6a 2a 62 7f b9 f9 b1 a0 e9 a9 e1 f0 b8 f8 b0 a1 e8 a8 e0 f1 5d 1d 55 84 cd 8d c5 14 5c 1c 54 85 cc 8c c4 15 bd fd b5 a4 ed ad e5 f4 bc fc b4 a5 ec ac e4 f5 39 79 31 20 69 29 61 70 38 78 30 21 68 28 60 71 b7 f7 bf a2 e7 a7 ef f2 ba fa b2 af ea aa e2 ff }

  condition:
    $a0
}