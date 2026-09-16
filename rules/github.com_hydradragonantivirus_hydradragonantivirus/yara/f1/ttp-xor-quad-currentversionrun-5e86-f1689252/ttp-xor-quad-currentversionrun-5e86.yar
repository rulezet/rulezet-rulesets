rule TTP_XOR_QUAD_CurrentVersionRun_5e86 {
  strings:
    $key_5e86 = { 0d e9 [2] 29 e7 [2] 02 cb [2] 2c e9 [2] 38 f2 [2] 37 e8 [2] 29 f5 [2] 2b f4 [2] 30 f2 [2] 2c f5 [2] 30 da }

  condition:
    any of them
}