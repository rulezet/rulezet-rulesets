rule TTP_XOR_QUAD_CurrentVersionRun_4b95 {
  strings:
    $key_4b95 = { 18 fa [2] 3c f4 [2] 17 d8 [2] 39 fa [2] 2d e1 [2] 22 fb [2] 3c e6 [2] 3e e7 [2] 25 e1 [2] 39 e6 [2] 25 c9 }

  condition:
    any of them
}