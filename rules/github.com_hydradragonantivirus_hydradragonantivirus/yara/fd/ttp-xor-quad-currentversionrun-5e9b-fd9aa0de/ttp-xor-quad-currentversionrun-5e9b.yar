rule TTP_XOR_QUAD_CurrentVersionRun_5e9b {
  strings:
    $key_5e9b = { 0d f4 [2] 29 fa [2] 02 d6 [2] 2c f4 [2] 38 ef [2] 37 f5 [2] 29 e8 [2] 2b e9 [2] 30 ef [2] 2c e8 [2] 30 c7 }

  condition:
    any of them
}