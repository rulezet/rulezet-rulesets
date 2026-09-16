rule TTP_XOR_QUAD_CurrentVersionRun_7089 {
  strings:
    $key_7089 = { 23 e6 [2] 07 e8 [2] 2c c4 [2] 02 e6 [2] 16 fd [2] 19 e7 [2] 07 fa [2] 05 fb [2] 1e fd [2] 02 fa [2] 1e d5 }

  condition:
    any of them
}