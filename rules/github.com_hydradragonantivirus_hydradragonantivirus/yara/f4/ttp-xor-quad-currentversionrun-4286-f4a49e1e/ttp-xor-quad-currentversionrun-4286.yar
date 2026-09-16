rule TTP_XOR_QUAD_CurrentVersionRun_4286 {
  strings:
    $key_4286 = { 11 e9 [2] 35 e7 [2] 1e cb [2] 30 e9 [2] 24 f2 [2] 2b e8 [2] 35 f5 [2] 37 f4 [2] 2c f2 [2] 30 f5 [2] 2c da }

  condition:
    any of them
}