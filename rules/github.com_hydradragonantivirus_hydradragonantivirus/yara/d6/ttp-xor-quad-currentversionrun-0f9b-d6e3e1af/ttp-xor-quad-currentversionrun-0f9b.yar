rule TTP_XOR_QUAD_CurrentVersionRun_0f9b {
  strings:
    $key_0f9b = { 5c f4 [2] 78 fa [2] 53 d6 [2] 7d f4 [2] 69 ef [2] 66 f5 [2] 78 e8 [2] 7a e9 [2] 61 ef [2] 7d e8 [2] 61 c7 }

  condition:
    any of them
}