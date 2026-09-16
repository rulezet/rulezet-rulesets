rule TTP_XOR_QUAD_CurrentVersionRun_5cc9 {
  strings:
    $key_5cc9 = { 0f a6 [2] 2b a8 [2] 00 84 [2] 2e a6 [2] 3a bd [2] 35 a7 [2] 2b ba [2] 29 bb [2] 32 bd [2] 2e ba [2] 32 95 }

  condition:
    any of them
}