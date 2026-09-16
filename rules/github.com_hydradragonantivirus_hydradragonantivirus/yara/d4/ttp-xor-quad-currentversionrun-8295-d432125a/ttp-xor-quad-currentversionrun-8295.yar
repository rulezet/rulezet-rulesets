rule TTP_XOR_QUAD_CurrentVersionRun_8295 {
  strings:
    $key_8295 = { d1 fa [2] f5 f4 [2] de d8 [2] f0 fa [2] e4 e1 [2] eb fb [2] f5 e6 [2] f7 e7 [2] ec e1 [2] f0 e6 [2] ec c9 }

  condition:
    any of them
}