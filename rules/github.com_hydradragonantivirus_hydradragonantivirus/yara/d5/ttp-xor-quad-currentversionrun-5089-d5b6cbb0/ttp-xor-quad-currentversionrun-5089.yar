rule TTP_XOR_QUAD_CurrentVersionRun_5089 {
  strings:
    $key_5089 = { 03 e6 [2] 27 e8 [2] 0c c4 [2] 22 e6 [2] 36 fd [2] 39 e7 [2] 27 fa [2] 25 fb [2] 3e fd [2] 22 fa [2] 3e d5 }

  condition:
    any of them
}