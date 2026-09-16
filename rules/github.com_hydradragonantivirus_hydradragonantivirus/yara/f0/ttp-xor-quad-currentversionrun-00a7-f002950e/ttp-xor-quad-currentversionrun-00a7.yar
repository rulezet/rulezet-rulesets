rule TTP_XOR_QUAD_CurrentVersionRun_00a7 {
  strings:
    $key_00a7 = { 53 c8 [2] 77 c6 [2] 5c ea [2] 72 c8 [2] 66 d3 [2] 69 c9 [2] 77 d4 [2] 75 d5 [2] 6e d3 [2] 72 d4 [2] 6e fb }

  condition:
    any of them
}