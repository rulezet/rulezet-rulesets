rule TTP_XOR_QUAD_CurrentVersionRun_8186 {
  strings:
    $key_8186 = { d2 e9 [2] f6 e7 [2] dd cb [2] f3 e9 [2] e7 f2 [2] e8 e8 [2] f6 f5 [2] f4 f4 [2] ef f2 [2] f3 f5 [2] ef da }

  condition:
    any of them
}