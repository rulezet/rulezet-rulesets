rule TTP_XOR_QUAD_CurrentVersionRun_6a9b {
  strings:
    $key_6a9b = { 39 f4 [2] 1d fa [2] 36 d6 [2] 18 f4 [2] 0c ef [2] 03 f5 [2] 1d e8 [2] 1f e9 [2] 04 ef [2] 18 e8 [2] 04 c7 }

  condition:
    any of them
}