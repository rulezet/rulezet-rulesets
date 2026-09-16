rule TTP_XOR_QUAD_CurrentVersionRun_4289 {
  strings:
    $key_4289 = { 11 e6 [2] 35 e8 [2] 1e c4 [2] 30 e6 [2] 24 fd [2] 2b e7 [2] 35 fa [2] 37 fb [2] 2c fd [2] 30 fa [2] 2c d5 }

  condition:
    any of them
}