rule TTP_XOR_QUAD_CurrentVersionRun_8662 {
  strings:
    $key_8662 = { d5 0d [2] f1 03 [2] da 2f [2] f4 0d [2] e0 16 [2] ef 0c [2] f1 11 [2] f3 10 [2] e8 16 [2] f4 11 [2] e8 3e }

  condition:
    any of them
}