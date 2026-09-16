rule TTP_XOR_QUAD_CurrentVersionRun_3594 {
  strings:
    $key_3594 = { 66 fb [2] 42 f5 [2] 69 d9 [2] 47 fb [2] 53 e0 [2] 5c fa [2] 42 e7 [2] 40 e6 [2] 5b e0 [2] 47 e7 [2] 5b c8 }

  condition:
    any of them
}