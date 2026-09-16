rule TTP_XOR_QUAD_CurrentVersionRun_3989 {
  strings:
    $key_3989 = { 6a e6 [2] 4e e8 [2] 65 c4 [2] 4b e6 [2] 5f fd [2] 50 e7 [2] 4e fa [2] 4c fb [2] 57 fd [2] 4b fa [2] 57 d5 }

  condition:
    any of them
}