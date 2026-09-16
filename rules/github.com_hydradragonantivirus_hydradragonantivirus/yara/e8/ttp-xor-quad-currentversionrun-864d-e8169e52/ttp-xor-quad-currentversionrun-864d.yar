rule TTP_XOR_QUAD_CurrentVersionRun_864d {
  strings:
    $key_864d = { d5 22 [2] f1 2c [2] da 00 [2] f4 22 [2] e0 39 [2] ef 23 [2] f1 3e [2] f3 3f [2] e8 39 [2] f4 3e [2] e8 11 }

  condition:
    any of them
}