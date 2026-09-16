rule libavcodec_imc_exp_tab__flt32___32_big_128_ {
  strings:
    $a0 = { 39 3a 77 57 39 a5 cb 60 3a 13 6a 16 3a 83 12 6f 3a e9 15 2d 3b 4f 3e 39 3b b8 44 9b 3c 23 d7 0a 3c 91 ad 3c 3d 01 86 e3 3d 66 55 c2 3d cc cc cd 3e 36 18 8b 3e a1 e8 9c 3f 0f f5 99 3f 80 00 00 3f e3 9e ae 40 4a 62 c3 40 b3 f3 00 41 20 00 00 41 8e 43 2d 41 fc fb 74 42 60 ef c0 42 c8 00 00 43 31 d3 f8 43 9e 1d 29 44 0c 95 d8 44 7a 00 00 44 de 48 f6 45 45 a4 73 45 af bb 4e 46 1c 40 00 }

  condition:
    $a0
}