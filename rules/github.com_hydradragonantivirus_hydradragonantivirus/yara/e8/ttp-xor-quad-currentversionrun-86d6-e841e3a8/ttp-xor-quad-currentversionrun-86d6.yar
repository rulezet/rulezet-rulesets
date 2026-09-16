rule TTP_XOR_QUAD_CurrentVersionRun_86d6 {
  strings:
    $key_86d6 = { d5 b9 [2] f1 b7 [2] da 9b [2] f4 b9 [2] e0 a2 [2] ef b8 [2] f1 a5 [2] f3 a4 [2] e8 a2 [2] f4 a5 [2] e8 8a }

  condition:
    any of them
}