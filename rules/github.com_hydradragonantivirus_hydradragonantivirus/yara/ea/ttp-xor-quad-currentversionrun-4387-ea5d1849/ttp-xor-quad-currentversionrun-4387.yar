rule TTP_XOR_QUAD_CurrentVersionRun_4387 {
  strings:
    $key_4387 = { 10 e8 [2] 34 e6 [2] 1f ca [2] 31 e8 [2] 25 f3 [2] 2a e9 [2] 34 f4 [2] 36 f5 [2] 2d f3 [2] 31 f4 [2] 2d db }

  condition:
    any of them
}