rule TTP_XOR_QUAD_CurrentVersionRun_7189 {
  strings:
    $key_7189 = { 22 e6 [2] 06 e8 [2] 2d c4 [2] 03 e6 [2] 17 fd [2] 18 e7 [2] 06 fa [2] 04 fb [2] 1f fd [2] 03 fa [2] 1f d5 }

  condition:
    any of them
}