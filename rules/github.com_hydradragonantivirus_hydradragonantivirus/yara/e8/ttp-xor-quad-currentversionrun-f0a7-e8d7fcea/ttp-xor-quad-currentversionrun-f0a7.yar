rule TTP_XOR_QUAD_CurrentVersionRun_f0a7 {
  strings:
    $key_f0a7 = { a3 c8 [2] 87 c6 [2] ac ea [2] 82 c8 [2] 96 d3 [2] 99 c9 [2] 87 d4 [2] 85 d5 [2] 9e d3 [2] 82 d4 [2] 9e fb }

  condition:
    any of them
}