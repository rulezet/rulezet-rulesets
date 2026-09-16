rule TTP_XOR_QUAD_CurrentVersionRun_5a95 {
  strings:
    $key_5a95 = { 09 fa [2] 2d f4 [2] 06 d8 [2] 28 fa [2] 3c e1 [2] 33 fb [2] 2d e6 [2] 2f e7 [2] 34 e1 [2] 28 e6 [2] 34 c9 }

  condition:
    any of them
}