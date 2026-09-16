rule TTP_XOR_QUAD_CurrentVersionRun_5a9b {
  strings:
    $key_5a9b = { 09 f4 [2] 2d fa [2] 06 d6 [2] 28 f4 [2] 3c ef [2] 33 f5 [2] 2d e8 [2] 2f e9 [2] 34 ef [2] 28 e8 [2] 34 c7 }

  condition:
    any of them
}