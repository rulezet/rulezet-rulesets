rule TTP_XOR_QUAD_CurrentVersionRun_81c6 {
  strings:
    $key_81c6 = { d2 a9 [2] f6 a7 [2] dd 8b [2] f3 a9 [2] e7 b2 [2] e8 a8 [2] f6 b5 [2] f4 b4 [2] ef b2 [2] f3 b5 [2] ef 9a }

  condition:
    any of them
}