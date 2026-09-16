rule TTP_XOR_QUAD_CurrentVersionRun_60a7 {
  strings:
    $key_60a7 = { 33 c8 [2] 17 c6 [2] 3c ea [2] 12 c8 [2] 06 d3 [2] 09 c9 [2] 17 d4 [2] 15 d5 [2] 0e d3 [2] 12 d4 [2] 0e fb }

  condition:
    any of them
}