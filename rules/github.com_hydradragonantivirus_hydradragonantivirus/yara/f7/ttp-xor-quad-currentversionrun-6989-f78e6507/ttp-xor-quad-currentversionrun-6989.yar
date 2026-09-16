rule TTP_XOR_QUAD_CurrentVersionRun_6989 {
  strings:
    $key_6989 = { 3a e6 [2] 1e e8 [2] 35 c4 [2] 1b e6 [2] 0f fd [2] 00 e7 [2] 1e fa [2] 1c fb [2] 07 fd [2] 1b fa [2] 07 d5 }

  condition:
    any of them
}