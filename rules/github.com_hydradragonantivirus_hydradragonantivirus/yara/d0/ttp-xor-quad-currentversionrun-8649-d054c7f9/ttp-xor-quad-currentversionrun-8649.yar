rule TTP_XOR_QUAD_CurrentVersionRun_8649 {
  strings:
    $key_8649 = { d5 26 [2] f1 28 [2] da 04 [2] f4 26 [2] e0 3d [2] ef 27 [2] f1 3a [2] f3 3b [2] e8 3d [2] f4 3a [2] e8 15 }

  condition:
    any of them
}