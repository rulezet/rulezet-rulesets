rule EPWIC_15_tap_hi_filter__flt32___32_big_60_ {
  strings:
    $a0 = { 3a a3 83 e5 bb 23 84 ad bc 0f 0c 45 3c a3 7e df 3d 4e f7 7f bd f6 e3 6d be 96 0a 12 3f 34 c7 f6 be 96 0a 12 bd f6 e3 6d 3d 4e f7 7f 3c a3 7e df bc 0f 0c 45 bb 23 84 ad 3a a3 83 e5 }

  condition:
    $a0
}