rule TTP_XOR_QUAD_CurrentVersionRun_7ba7 {
  strings:
    $key_7ba7 = { 28 c8 [2] 0c c6 [2] 27 ea [2] 09 c8 [2] 1d d3 [2] 12 c9 [2] 0c d4 [2] 0e d5 [2] 15 d3 [2] 09 d4 [2] 15 fb }

  condition:
    any of them
}