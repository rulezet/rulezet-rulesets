rule TTP_XOR_QUAD_CurrentVersionRun_81a9 {
  strings:
    $key_81a9 = { d2 c6 [2] f6 c8 [2] dd e4 [2] f3 c6 [2] e7 dd [2] e8 c7 [2] f6 da [2] f4 db [2] ef dd [2] f3 da [2] ef f5 }

  condition:
    any of them
}