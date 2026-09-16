rule TTP_XOR_QUAD_CurrentVersionRun_3b95 {
  strings:
    $key_3b95 = { 68 fa [2] 4c f4 [2] 67 d8 [2] 49 fa [2] 5d e1 [2] 52 fb [2] 4c e6 [2] 4e e7 [2] 55 e1 [2] 49 e6 [2] 55 c9 }

  condition:
    any of them
}