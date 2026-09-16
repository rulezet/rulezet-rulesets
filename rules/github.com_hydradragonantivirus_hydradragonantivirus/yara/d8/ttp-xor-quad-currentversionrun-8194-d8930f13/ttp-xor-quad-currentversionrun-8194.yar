rule TTP_XOR_QUAD_CurrentVersionRun_8194 {
  strings:
    $key_8194 = { d2 fb [2] f6 f5 [2] dd d9 [2] f3 fb [2] e7 e0 [2] e8 fa [2] f6 e7 [2] f4 e6 [2] ef e0 [2] f3 e7 [2] ef c8 }

  condition:
    any of them
}