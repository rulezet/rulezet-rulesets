rule TTP_XOR_QUAD_CurrentVersionRun_7e95 {
  strings:
    $key_7e95 = { 2d fa [2] 09 f4 [2] 22 d8 [2] 0c fa [2] 18 e1 [2] 17 fb [2] 09 e6 [2] 0b e7 [2] 10 e1 [2] 0c e6 [2] 10 c9 }

  condition:
    any of them
}