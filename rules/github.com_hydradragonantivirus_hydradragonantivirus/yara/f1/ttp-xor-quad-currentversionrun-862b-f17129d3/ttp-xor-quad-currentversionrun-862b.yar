rule TTP_XOR_QUAD_CurrentVersionRun_862b {
  strings:
    $key_862b = { d5 44 [2] f1 4a [2] da 66 [2] f4 44 [2] e0 5f [2] ef 45 [2] f1 58 [2] f3 59 [2] e8 5f [2] f4 58 [2] e8 77 }

  condition:
    any of them
}