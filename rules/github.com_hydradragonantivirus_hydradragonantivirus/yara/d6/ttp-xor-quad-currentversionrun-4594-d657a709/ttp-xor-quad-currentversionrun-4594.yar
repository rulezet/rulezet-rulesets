rule TTP_XOR_QUAD_CurrentVersionRun_4594 {
  strings:
    $key_4594 = { 16 fb [2] 32 f5 [2] 19 d9 [2] 37 fb [2] 23 e0 [2] 2c fa [2] 32 e7 [2] 30 e6 [2] 2b e0 [2] 37 e7 [2] 2b c8 }

  condition:
    any of them
}