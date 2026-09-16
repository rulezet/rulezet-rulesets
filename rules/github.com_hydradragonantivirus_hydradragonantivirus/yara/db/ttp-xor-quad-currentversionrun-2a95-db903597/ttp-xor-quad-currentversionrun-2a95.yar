rule TTP_XOR_QUAD_CurrentVersionRun_2a95 {
  strings:
    $key_2a95 = { 79 fa [2] 5d f4 [2] 76 d8 [2] 58 fa [2] 4c e1 [2] 43 fb [2] 5d e6 [2] 5f e7 [2] 44 e1 [2] 58 e6 [2] 44 c9 }

  condition:
    any of them
}