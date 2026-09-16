rule TTP_XOR_QUAD_CurrentVersionRun_3189 {
  strings:
    $key_3189 = { 62 e6 [2] 46 e8 [2] 6d c4 [2] 43 e6 [2] 57 fd [2] 58 e7 [2] 46 fa [2] 44 fb [2] 5f fd [2] 43 fa [2] 5f d5 }

  condition:
    any of them
}