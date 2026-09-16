rule US_ASCII_to_EBCDIC__character_set_IBM_1047__table__8_byt_256_ {
  strings:
    $a0 = { 00 01 02 03 37 2d 2e 2f 16 05 15 0b 0c 0d 0e 0f 10 11 12 13 3c 3d 32 26 18 19 3f 27 1c 1d 1e 1f 40 5a 7f 7b 5b 6c 50 7d 4d 5d 5c 4e 6b 60 4b 61 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 7a 5e 4c 7e 6e 6f 7c c1 c2 c3 c4 c5 c6 c7 c8 c9 d1 d2 d3 d4 d5 d6 d7 d8 d9 e2 e3 e4 e5 e6 e7 e8 e9 ad e0 bd 5f 6d 79 81 82 83 84 85 86 87 88 89 91 92 93 94 95 96 97 98 99 a2 a3 a4 a5 a6 a7 a8 a9 c0 4f d0 a1 07 20 21 22 23 24 04 06 08 28 29 2a 2b 2c 09 0a 14 30 31 25 33 34 35 36 17 38 39 3a 3b 1a 1b 3e ff 41 aa 4a b1 9f b2 6a b5 bb b4 9a 8a b0 ca af bc 90 8f ea fa be a0 b6 b3 9d da 9b 8b b7 b8 b9 ab 64 65 62 66 63 67 9e 68 74 71 72 73 78 75 76 77 ac 69 ed ee eb ef ec bf 80 fd fe fb fc ba ae 59 44 45 42 46 43 47 9c 48 54 51 52 53 58 55 56 57 8c 49 cd ce cb cf cc e1 70 dd de db dc 8d 8e df }

  condition:
    $a0
}