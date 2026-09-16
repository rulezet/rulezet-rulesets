rule TTP_XOR_QUAD_CurrentVersionRun_4a95 {
  strings:
    $key_4a95 = { 19 fa [2] 3d f4 [2] 16 d8 [2] 38 fa [2] 2c e1 [2] 23 fb [2] 3d e6 [2] 3f e7 [2] 24 e1 [2] 38 e6 [2] 24 c9 }

  condition:
    any of them
}