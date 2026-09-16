rule EPWIC_old_15_tap_filter__flt32___32_big_60_ {
  strings:
    $a0 = { ba a0 b9 c1 bb 71 16 5c 3c 0c a2 17 3c aa c7 06 bd 4d f2 b3 bd f8 92 16 3e 95 fa 00 3f 35 5a 42 3e 95 fa 00 bd f8 92 16 bd 4d f2 b3 3c aa c7 06 3c 0c a2 17 bb 71 16 5c ba a0 b9 c1 }

  condition:
    $a0
}