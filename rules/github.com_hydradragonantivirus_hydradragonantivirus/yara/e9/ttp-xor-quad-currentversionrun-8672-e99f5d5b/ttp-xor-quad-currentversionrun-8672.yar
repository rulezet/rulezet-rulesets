rule TTP_XOR_QUAD_CurrentVersionRun_8672 {
  strings:
    $key_8672 = { d5 1d [2] f1 13 [2] da 3f [2] f4 1d [2] e0 06 [2] ef 1c [2] f1 01 [2] f3 00 [2] e8 06 [2] f4 01 [2] e8 2e }

  condition:
    any of them
}