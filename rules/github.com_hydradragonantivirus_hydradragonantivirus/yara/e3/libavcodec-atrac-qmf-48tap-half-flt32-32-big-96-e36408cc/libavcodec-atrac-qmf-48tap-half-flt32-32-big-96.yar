rule libavcodec_atrac_qmf_48tap_half__flt32___32_big_96_ {
  strings:
    $a0 = { b7 75 44 6d b8 c1 0d 8a b8 6b 8a bb 39 9d e6 b7 39 7e 05 00 ba 5f 97 c4 ba 08 76 04 3b 05 4d 24 3a 4d 58 fc bb 8a 21 39 ba 46 38 5c 3c 00 74 94 b8 80 48 5a bc 5c 3a 3e 3b 21 64 f3 3c b2 0f e2 bb ff a5 29 bd 0b a2 30 3c 9a 16 5c 3d 5e 84 f3 bd 32 92 1e bd cb 8a 08 3e 07 3f be 3e ed b1 13 }

  condition:
    $a0
}