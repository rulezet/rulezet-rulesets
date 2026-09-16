rule TTP_XOR_QUAD_CurrentVersionRun_40c9 {
  strings:
    $key_40c9 = { 13 a6 [2] 37 a8 [2] 1c 84 [2] 32 a6 [2] 26 bd [2] 29 a7 [2] 37 ba [2] 35 bb [2] 2e bd [2] 32 ba [2] 2e 95 }

  condition:
    any of them
}