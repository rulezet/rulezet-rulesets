rule TTP_XOR_QUAD_CurrentVersionRun_4089 {
  strings:
    $key_4089 = { 13 e6 [2] 37 e8 [2] 1c c4 [2] 32 e6 [2] 26 fd [2] 29 e7 [2] 37 fa [2] 35 fb [2] 2e fd [2] 32 fa [2] 2e d5 }

  condition:
    any of them
}