rule TTP_XOR_QUAD_CurrentVersionRun_42d4 {
  strings:
    $key_42d4 = { 11 bb [2] 35 b5 [2] 1e 99 [2] 30 bb [2] 24 a0 [2] 2b ba [2] 35 a7 [2] 37 a6 [2] 2c a0 [2] 30 a7 [2] 2c 88 }

  condition:
    any of them
}