rule TTP_XOR_QUAD_CurrentVersionRun_6295 {
  strings:
    $key_6295 = { 31 fa [2] 15 f4 [2] 3e d8 [2] 10 fa [2] 04 e1 [2] 0b fb [2] 15 e6 [2] 17 e7 [2] 0c e1 [2] 10 e6 [2] 0c c9 }

  condition:
    any of them
}