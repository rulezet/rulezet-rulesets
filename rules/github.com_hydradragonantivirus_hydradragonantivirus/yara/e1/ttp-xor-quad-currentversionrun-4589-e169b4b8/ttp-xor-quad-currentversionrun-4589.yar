rule TTP_XOR_QUAD_CurrentVersionRun_4589 {
  strings:
    $key_4589 = { 16 e6 [2] 32 e8 [2] 19 c4 [2] 37 e6 [2] 23 fd [2] 2c e7 [2] 32 fa [2] 30 fb [2] 2b fd [2] 37 fa [2] 2b d5 }

  condition:
    any of them
}