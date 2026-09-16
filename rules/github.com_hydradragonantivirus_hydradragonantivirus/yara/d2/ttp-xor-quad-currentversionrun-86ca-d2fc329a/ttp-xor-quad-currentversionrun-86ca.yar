rule TTP_XOR_QUAD_CurrentVersionRun_86ca {
  strings:
    $key_86ca = { d5 a5 [2] f1 ab [2] da 87 [2] f4 a5 [2] e0 be [2] ef a4 [2] f1 b9 [2] f3 b8 [2] e8 be [2] f4 b9 [2] e8 96 }

  condition:
    any of them
}