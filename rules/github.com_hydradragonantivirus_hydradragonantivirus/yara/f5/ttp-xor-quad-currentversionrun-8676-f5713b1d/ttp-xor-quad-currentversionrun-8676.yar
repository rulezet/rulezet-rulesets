rule TTP_XOR_QUAD_CurrentVersionRun_8676 {
  strings:
    $key_8676 = { d5 19 [2] f1 17 [2] da 3b [2] f4 19 [2] e0 02 [2] ef 18 [2] f1 05 [2] f3 04 [2] e8 02 [2] f4 05 [2] e8 2a }

  condition:
    any of them
}