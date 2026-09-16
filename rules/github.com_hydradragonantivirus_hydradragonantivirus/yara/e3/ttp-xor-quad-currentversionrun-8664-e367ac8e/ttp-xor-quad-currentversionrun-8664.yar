rule TTP_XOR_QUAD_CurrentVersionRun_8664 {
  strings:
    $key_8664 = { d5 0b [2] f1 05 [2] da 29 [2] f4 0b [2] e0 10 [2] ef 0a [2] f1 17 [2] f3 16 [2] e8 10 [2] f4 17 [2] e8 38 }

  condition:
    any of them
}