rule TTP_XOR_QUAD_CurrentVersionRun_5189 {
  strings:
    $key_5189 = { 02 e6 [2] 26 e8 [2] 0d c4 [2] 23 e6 [2] 37 fd [2] 38 e7 [2] 26 fa [2] 24 fb [2] 3f fd [2] 23 fa [2] 3f d5 }

  condition:
    any of them
}