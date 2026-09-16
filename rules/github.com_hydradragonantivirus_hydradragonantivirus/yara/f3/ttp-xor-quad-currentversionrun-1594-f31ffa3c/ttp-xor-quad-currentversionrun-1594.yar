rule TTP_XOR_QUAD_CurrentVersionRun_1594 {
  strings:
    $key_1594 = { 46 fb [2] 62 f5 [2] 49 d9 [2] 67 fb [2] 73 e0 [2] 7c fa [2] 62 e7 [2] 60 e6 [2] 7b e0 [2] 67 e7 [2] 7b c8 }

  condition:
    any of them
}