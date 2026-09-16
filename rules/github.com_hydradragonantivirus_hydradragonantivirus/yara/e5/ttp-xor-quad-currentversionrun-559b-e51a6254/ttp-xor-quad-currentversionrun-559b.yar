rule TTP_XOR_QUAD_CurrentVersionRun_559b {
  strings:
    $key_559b = { 06 f4 [2] 22 fa [2] 09 d6 [2] 27 f4 [2] 33 ef [2] 3c f5 [2] 22 e8 [2] 20 e9 [2] 3b ef [2] 27 e8 [2] 3b c7 }

  condition:
    any of them
}