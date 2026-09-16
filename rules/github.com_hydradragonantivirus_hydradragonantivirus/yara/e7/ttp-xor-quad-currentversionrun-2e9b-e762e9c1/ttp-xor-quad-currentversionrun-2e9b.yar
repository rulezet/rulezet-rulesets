rule TTP_XOR_QUAD_CurrentVersionRun_2e9b {
  strings:
    $key_2e9b = { 7d f4 [2] 59 fa [2] 72 d6 [2] 5c f4 [2] 48 ef [2] 47 f5 [2] 59 e8 [2] 5b e9 [2] 40 ef [2] 5c e8 [2] 40 c7 }

  condition:
    any of them
}