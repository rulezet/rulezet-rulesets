rule EPWIC_15_tap_lo_filter__flt32___32_big_60_ {
  strings:
    $a0 = { ba a3 83 e5 bb 23 84 ad 3c 0f 0c 45 3c a3 7e df bd 4e f7 7f bd f6 e3 6d 3e 96 0a 12 3f 34 c7 f6 3e 96 0a 12 bd f6 e3 6d bd 4e f7 7f 3c a3 7e df 3c 0f 0c 45 bb 23 84 ad ba a3 83 e5 }

  condition:
    $a0
}