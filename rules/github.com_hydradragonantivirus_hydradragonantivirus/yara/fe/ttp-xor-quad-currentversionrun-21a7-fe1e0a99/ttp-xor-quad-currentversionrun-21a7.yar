rule TTP_XOR_QUAD_CurrentVersionRun_21a7 {
  strings:
    $key_21a7 = { 72 c8 [2] 56 c6 [2] 7d ea [2] 53 c8 [2] 47 d3 [2] 48 c9 [2] 56 d4 [2] 54 d5 [2] 4f d3 [2] 53 d4 [2] 4f fb }

  condition:
    any of them
}