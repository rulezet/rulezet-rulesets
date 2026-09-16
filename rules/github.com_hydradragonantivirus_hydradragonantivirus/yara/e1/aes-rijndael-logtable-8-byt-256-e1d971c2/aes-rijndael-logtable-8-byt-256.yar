rule AES_Rijndael_Logtable__8_byt_256_ {
  strings:
    $a0 = { 00 00 19 01 32 02 1a c6 4b c7 1b 68 33 ee df 03 64 04 e0 0e 34 8d 81 ef 4c 71 08 c8 f8 69 1c c1 7d c2 1d b5 f9 b9 27 6a 4d e4 a6 72 9a c9 09 78 65 2f 8a 05 21 0f e1 24 12 f0 82 45 35 93 da 8e 96 8f db bd 36 d0 ce 94 13 5c d2 f1 40 46 83 38 66 dd fd 30 bf 06 8b 62 b3 25 e2 98 22 88 91 10 7e 6e 48 c3 a3 b6 1e 42 3a 6b 28 54 fa 85 3d ba 2b 79 0a 15 9b 9f 5e ca 4e d4 ac e5 f3 73 a7 57 af 58 a8 50 f4 ea d6 74 4f ae e9 d5 e7 e6 ad e8 2c d7 75 7a eb 16 0b f5 59 cb 5f b0 9c a9 51 a0 7f 0c f6 6f 17 c4 49 ec d8 43 1f 2d a4 76 7b b7 cc bb 3e 5a fb 60 b1 86 3b 52 a1 6c aa 55 29 9d 97 b2 87 90 61 be dc fc bc 95 cf cd 37 3f 5b d1 53 39 84 3c 41 a2 6d 47 14 2a 9e 5d 56 f2 d3 ab 44 11 92 d9 23 20 2e 89 b4 7c b8 26 77 99 e3 a5 67 4a ed de c5 31 fe 18 0d 63 8c 80 c0 f7 70 07 }

  condition:
    $a0
}