rule TTP_XOR_QUAD_CurrentVersionRun_42c8 {
  strings:
    $key_42c8 = { 11 a7 [2] 35 a9 [2] 1e 85 [2] 30 a7 [2] 24 bc [2] 2b a6 [2] 35 bb [2] 37 ba [2] 2c bc [2] 30 bb [2] 2c 94 }

  condition:
    any of them
}