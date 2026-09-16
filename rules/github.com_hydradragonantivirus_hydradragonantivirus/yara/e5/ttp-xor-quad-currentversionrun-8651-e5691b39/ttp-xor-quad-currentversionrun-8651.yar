rule TTP_XOR_QUAD_CurrentVersionRun_8651 {
  strings:
    $key_8651 = { d5 3e [2] f1 30 [2] da 1c [2] f4 3e [2] e0 25 [2] ef 3f [2] f1 22 [2] f3 23 [2] e8 25 [2] f4 22 [2] e8 0d }

  condition:
    any of them
}