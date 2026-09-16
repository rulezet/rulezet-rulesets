rule TTP_XOR_QUAD_CurrentVersionRun_4287 {
  strings:
    $key_4287 = { 11 e8 [2] 35 e6 [2] 1e ca [2] 30 e8 [2] 24 f3 [2] 2b e9 [2] 35 f4 [2] 37 f5 [2] 2c f3 [2] 30 f4 [2] 2c db }

  condition:
    any of them
}