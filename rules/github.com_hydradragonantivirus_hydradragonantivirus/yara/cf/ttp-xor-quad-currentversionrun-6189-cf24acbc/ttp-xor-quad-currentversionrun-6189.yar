rule TTP_XOR_QUAD_CurrentVersionRun_6189 {
  strings:
    $key_6189 = { 32 e6 [2] 16 e8 [2] 3d c4 [2] 13 e6 [2] 07 fd [2] 08 e7 [2] 16 fa [2] 14 fb [2] 0f fd [2] 13 fa [2] 0f d5 }

  condition:
    any of them
}