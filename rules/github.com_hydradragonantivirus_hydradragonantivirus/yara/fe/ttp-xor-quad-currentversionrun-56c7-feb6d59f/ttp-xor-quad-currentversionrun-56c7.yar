rule TTP_XOR_QUAD_CurrentVersionRun_56c7 {
  strings:
    $key_56c7 = { 05 a8 [2] 21 a6 [2] 0a 8a [2] 24 a8 [2] 30 b3 [2] 3f a9 [2] 21 b4 [2] 23 b5 [2] 38 b3 [2] 24 b4 [2] 38 9b }

  condition:
    any of them
}