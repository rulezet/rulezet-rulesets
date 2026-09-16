rule TTP_XOR_QUAD_CurrentVersionRun_4cc9 {
  strings:
    $key_4cc9 = { 1f a6 [2] 3b a8 [2] 10 84 [2] 3e a6 [2] 2a bd [2] 25 a7 [2] 3b ba [2] 39 bb [2] 22 bd [2] 3e ba [2] 22 95 }

  condition:
    any of them
}