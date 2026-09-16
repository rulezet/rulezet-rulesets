rule TTP_XOR_QUAD_CurrentVersionRun_8657 {
  strings:
    $key_8657 = { d5 38 [2] f1 36 [2] da 1a [2] f4 38 [2] e0 23 [2] ef 39 [2] f1 24 [2] f3 25 [2] e8 23 [2] f4 24 [2] e8 0b }

  condition:
    any of them
}