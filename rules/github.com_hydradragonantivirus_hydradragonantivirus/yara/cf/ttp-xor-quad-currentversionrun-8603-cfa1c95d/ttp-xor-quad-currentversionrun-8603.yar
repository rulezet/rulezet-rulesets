rule TTP_XOR_QUAD_CurrentVersionRun_8603 {
  strings:
    $key_8603 = { d5 6c [2] f1 62 [2] da 4e [2] f4 6c [2] e0 77 [2] ef 6d [2] f1 70 [2] f3 71 [2] e8 77 [2] f4 70 [2] e8 5f }

  condition:
    any of them
}