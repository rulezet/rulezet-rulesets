rule TTP_XOR_QUAD_CurrentVersionRun_5986 {
  strings:
    $key_5986 = { 0a e9 [2] 2e e7 [2] 05 cb [2] 2b e9 [2] 3f f2 [2] 30 e8 [2] 2e f5 [2] 2c f4 [2] 37 f2 [2] 2b f5 [2] 37 da }

  condition:
    any of them
}