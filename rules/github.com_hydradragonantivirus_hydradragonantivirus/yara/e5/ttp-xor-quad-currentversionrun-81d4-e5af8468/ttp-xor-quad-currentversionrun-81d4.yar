rule TTP_XOR_QUAD_CurrentVersionRun_81d4 {
  strings:
    $key_81d4 = { d2 bb [2] f6 b5 [2] dd 99 [2] f3 bb [2] e7 a0 [2] e8 ba [2] f6 a7 [2] f4 a6 [2] ef a0 [2] f3 a7 [2] ef 88 }

  condition:
    any of them
}