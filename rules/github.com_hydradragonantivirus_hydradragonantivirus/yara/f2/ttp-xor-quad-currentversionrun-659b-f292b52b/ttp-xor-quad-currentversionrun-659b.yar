rule TTP_XOR_QUAD_CurrentVersionRun_659b {
  strings:
    $key_659b = { 36 f4 [2] 12 fa [2] 39 d6 [2] 17 f4 [2] 03 ef [2] 0c f5 [2] 12 e8 [2] 10 e9 [2] 0b ef [2] 17 e8 [2] 0b c7 }

  condition:
    any of them
}