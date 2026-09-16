rule TTP_XOR_QUAD_CurrentVersionRun_0387 {
  strings:
    $key_0387 = { 50 e8 [2] 74 e6 [2] 5f ca [2] 71 e8 [2] 65 f3 [2] 6a e9 [2] 74 f4 [2] 76 f5 [2] 6d f3 [2] 71 f4 [2] 6d db }

  condition:
    any of them
}