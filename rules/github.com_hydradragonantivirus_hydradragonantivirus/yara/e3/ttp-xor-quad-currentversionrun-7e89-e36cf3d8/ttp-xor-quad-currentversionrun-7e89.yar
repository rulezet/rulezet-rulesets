rule TTP_XOR_QUAD_CurrentVersionRun_7e89 {
  strings:
    $key_7e89 = { 2d e6 [2] 09 e8 [2] 22 c4 [2] 0c e6 [2] 18 fd [2] 17 e7 [2] 09 fa [2] 0b fb [2] 10 fd [2] 0c fa [2] 10 d5 }

  condition:
    any of them
}