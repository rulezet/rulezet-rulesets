rule TTP_XOR_QUAD_CurrentVersionRun_5a94 {
  strings:
    $key_5a94 = { 09 fb [2] 2d f5 [2] 06 d9 [2] 28 fb [2] 3c e0 [2] 33 fa [2] 2d e7 [2] 2f e6 [2] 34 e0 [2] 28 e7 [2] 34 c8 }

  condition:
    any of them
}