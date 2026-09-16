rule TTP_XOR_QUAD_CurrentVersionRun_8195 {
  strings:
    $key_8195 = { d2 fa [2] f6 f4 [2] dd d8 [2] f3 fa [2] e7 e1 [2] e8 fb [2] f6 e6 [2] f4 e7 [2] ef e1 [2] f3 e6 [2] ef c9 }

  condition:
    any of them
}