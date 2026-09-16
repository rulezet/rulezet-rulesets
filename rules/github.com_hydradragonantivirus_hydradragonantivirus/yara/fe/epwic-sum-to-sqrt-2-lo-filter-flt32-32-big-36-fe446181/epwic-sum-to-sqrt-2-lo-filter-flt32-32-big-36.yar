rule EPWIC_Sum_to_sqrt_2_lo_filter__flt32___32_big_36_ {
  strings:
    $a0 = { 3c e5 f6 41 bd 79 9b f8 bd 96 48 95 3e d4 52 73 3f 4c 1d b3 3e d4 52 73 bd 96 48 95 bd 79 9b f8 3c e5 f6 41 }

  condition:
    $a0
}