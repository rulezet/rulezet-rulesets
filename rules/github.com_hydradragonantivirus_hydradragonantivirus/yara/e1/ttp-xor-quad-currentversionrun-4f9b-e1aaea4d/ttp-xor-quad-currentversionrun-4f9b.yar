rule TTP_XOR_QUAD_CurrentVersionRun_4f9b {
  strings:
    $key_4f9b = { 1c f4 [2] 38 fa [2] 13 d6 [2] 3d f4 [2] 29 ef [2] 26 f5 [2] 38 e8 [2] 3a e9 [2] 21 ef [2] 3d e8 [2] 21 c7 }

  condition:
    any of them
}