rule TTP_XOR_QUAD_CurrentVersionRun_fba7 {
  strings:
    $key_fba7 = { a8 c8 [2] 8c c6 [2] a7 ea [2] 89 c8 [2] 9d d3 [2] 92 c9 [2] 8c d4 [2] 8e d5 [2] 95 d3 [2] 89 d4 [2] 95 fb }

  condition:
    any of them
}