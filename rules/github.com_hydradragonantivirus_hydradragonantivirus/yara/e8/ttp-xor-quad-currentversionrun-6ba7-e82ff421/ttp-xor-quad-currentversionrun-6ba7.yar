rule TTP_XOR_QUAD_CurrentVersionRun_6ba7 {
  strings:
    $key_6ba7 = { 38 c8 [2] 1c c6 [2] 37 ea [2] 19 c8 [2] 0d d3 [2] 02 c9 [2] 1c d4 [2] 1e d5 [2] 05 d3 [2] 19 d4 [2] 05 fb }

  condition:
    any of them
}