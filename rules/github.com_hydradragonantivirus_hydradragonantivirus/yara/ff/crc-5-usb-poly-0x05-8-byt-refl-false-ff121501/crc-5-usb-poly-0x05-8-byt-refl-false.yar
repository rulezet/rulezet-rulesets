rule CRC_5_USB_poly_0x05__8_byt_refl_False_ {
  strings:
    $a0 = { 00 05 0a 0f 14 11 1e 1b 28 2d 22 27 3c 39 36 33 50 55 5a 5f 44 41 4e 4b 78 7d 72 77 6c 69 66 63 a0 a5 aa af b4 b1 be bb 88 8d 82 87 9c 99 96 93 f0 f5 fa ff e4 e1 ee eb d8 dd d2 d7 cc c9 c6 c3 45 40 4f 4a 51 54 5b 5e 6d 68 67 62 79 7c 73 76 15 10 1f 1a 01 04 0b 0e 3d 38 37 32 29 2c 23 26 e5 e0 ef ea f1 f4 fb fe cd c8 c7 c2 d9 dc d3 d6 b5 b0 bf ba a1 a4 ab ae 9d 98 97 92 89 8c 83 86 8a 8f 80 85 9e 9b 94 91 a2 a7 a8 ad b6 b3 bc b9 da df d0 d5 ce cb c4 c1 f2 f7 f8 fd e6 e3 ec e9 2a 2f 20 25 3e 3b 34 31 02 07 08 0d 16 13 1c 19 7a 7f 70 75 6e 6b 64 61 52 57 58 5d 46 43 4c 49 cf ca c5 c0 db de d1 d4 e7 e2 ed e8 f3 f6 f9 fc 9f 9a 95 90 8b 8e 81 84 b7 b2 bd b8 a3 a6 a9 ac 6f 6a 65 60 7b 7e 71 74 47 42 4d 48 53 56 59 5c 3f 3a 35 30 2b 2e 21 24 17 12 1d 18 03 06 09 0c }

  condition:
    $a0
}