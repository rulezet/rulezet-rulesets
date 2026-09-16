rule EC_curve__EC_SECG_CHAR2_163R1_SEED__8_byt_20_ {
  strings:
    $a0 = { 24 b7 b1 37 c8 a1 4d 69 6e 67 68 75 61 51 75 6f d0 da 2e 5c }

  condition:
    $a0
}