rule TTP_XOR_QUAD_CurrentVersionRun_1ba7 {
  strings:
    $key_1ba7 = { 48 c8 [2] 6c c6 [2] 47 ea [2] 69 c8 [2] 7d d3 [2] 72 c9 [2] 6c d4 [2] 6e d5 [2] 75 d3 [2] 69 d4 [2] 75 fb }

  condition:
    any of them
}