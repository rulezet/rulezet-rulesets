rule TTP_XOR_QUAD_CurrentVersionRun_7f9b {
  strings:
    $key_7f9b = { 2c f4 [2] 08 fa [2] 23 d6 [2] 0d f4 [2] 19 ef [2] 16 f5 [2] 08 e8 [2] 0a e9 [2] 11 ef [2] 0d e8 [2] 11 c7 }

  condition:
    any of them
}