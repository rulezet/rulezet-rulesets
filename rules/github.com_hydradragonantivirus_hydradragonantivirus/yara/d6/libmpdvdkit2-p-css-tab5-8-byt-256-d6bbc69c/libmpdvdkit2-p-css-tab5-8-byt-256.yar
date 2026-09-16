rule libmpdvdkit2_p_css_tab5__8_byt_256_ {
  strings:
    $a0 = { ff 7f bf 3f df 5f 9f 1f ef 6f af 2f cf 4f 8f 0f f7 77 b7 37 d7 57 97 17 e7 67 a7 27 c7 47 87 07 fb 7b bb 3b db 5b 9b 1b eb 6b ab 2b cb 4b 8b 0b f3 73 b3 33 d3 53 93 13 e3 63 a3 23 c3 43 83 03 fd 7d bd 3d dd 5d 9d 1d ed 6d ad 2d cd 4d 8d 0d f5 75 b5 35 d5 55 95 15 e5 65 a5 25 c5 45 85 05 f9 79 b9 39 d9 59 99 19 e9 69 a9 29 c9 49 89 09 f1 71 b1 31 d1 51 91 11 e1 61 a1 21 c1 41 81 01 fe 7e be 3e de 5e 9e 1e ee 6e ae 2e ce 4e 8e 0e f6 76 b6 36 d6 56 96 16 e6 66 a6 26 c6 46 86 06 fa 7a ba 3a da 5a 9a 1a ea 6a aa 2a ca 4a 8a 0a f2 72 b2 32 d2 52 92 12 e2 62 a2 22 c2 42 82 02 fc 7c bc 3c dc 5c 9c 1c ec 6c ac 2c cc 4c 8c 0c f4 74 b4 34 d4 54 94 14 e4 64 a4 24 c4 44 84 04 f8 78 b8 38 d8 58 98 18 e8 68 a8 28 c8 48 88 08 f0 70 b0 30 d0 50 90 10 e0 60 a0 20 c0 40 80 00 }

  condition:
    $a0
}