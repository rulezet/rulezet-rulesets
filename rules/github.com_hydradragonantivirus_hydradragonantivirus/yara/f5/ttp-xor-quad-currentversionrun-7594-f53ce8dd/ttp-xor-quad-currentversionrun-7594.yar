rule TTP_XOR_QUAD_CurrentVersionRun_7594 {
  strings:
    $key_7594 = { 26 fb [2] 02 f5 [2] 29 d9 [2] 07 fb [2] 13 e0 [2] 1c fa [2] 02 e7 [2] 00 e6 [2] 1b e0 [2] 07 e7 [2] 1b c8 }

  condition:
    any of them
}