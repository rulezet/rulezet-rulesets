rule MMX_codes__32_big_124_ {
  strings:
    $a0 = { 3f 00 27 85 3f 01 66 8b 3f 03 f4 5b 3f 07 f2 68 3f 0d 98 38 3f 15 3b 3a 3f 1f 5c 6e 3f 2c c0 3d 3f 3e 99 ee 3f 56 df 9e 3f 78 fa 3b 3f 95 b0 35 3f bd f9 1b 40 03 b2 af 40 5a 16 42 41 23 0a 46 3f 00 9e 8d 3f 05 c2 78 3f 11 23 3f 3f 25 96 1d 3f 49 c4 80 3f 87 c4 49 3f dc 79 26 40 a3 3c 9c 3f 02 81 f7 3f 19 f1 bd 3f 66 64 d7 40 24 06 cf 3f 0a 8b d4 3f a7 3d 75 3f 35 04 f3 }

  condition:
    $a0
}