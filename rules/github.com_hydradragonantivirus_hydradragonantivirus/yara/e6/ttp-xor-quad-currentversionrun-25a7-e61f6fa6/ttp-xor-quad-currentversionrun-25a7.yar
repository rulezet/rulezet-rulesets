rule TTP_XOR_QUAD_CurrentVersionRun_25a7 {
  strings:
    $key_25a7 = { 76 c8 [2] 52 c6 [2] 79 ea [2] 57 c8 [2] 43 d3 [2] 4c c9 [2] 52 d4 [2] 50 d5 [2] 4b d3 [2] 57 d4 [2] 4b fb }

  condition:
    any of them
}