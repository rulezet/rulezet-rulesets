rule TTP_XOR_QUAD_CurrentVersionRun_8674 {
  strings:
    $key_8674 = { d5 1b [2] f1 15 [2] da 39 [2] f4 1b [2] e0 00 [2] ef 1a [2] f1 07 [2] f3 06 [2] e8 00 [2] f4 07 [2] e8 28 }

  condition:
    any of them
}