rule TTP_XOR_QUAD_CurrentVersionRun_4e95 {
  strings:
    $key_4e95 = { 1d fa [2] 39 f4 [2] 12 d8 [2] 3c fa [2] 28 e1 [2] 27 fb [2] 39 e6 [2] 3b e7 [2] 20 e1 [2] 3c e6 [2] 20 c9 }

  condition:
    any of them
}