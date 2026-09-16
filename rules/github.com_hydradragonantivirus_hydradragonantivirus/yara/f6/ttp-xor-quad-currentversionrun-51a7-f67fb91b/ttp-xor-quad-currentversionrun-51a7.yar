rule TTP_XOR_QUAD_CurrentVersionRun_51a7 {
  strings:
    $key_51a7 = { 02 c8 [2] 26 c6 [2] 0d ea [2] 23 c8 [2] 37 d3 [2] 38 c9 [2] 26 d4 [2] 24 d5 [2] 3f d3 [2] 23 d4 [2] 3f fb }

  condition:
    any of them
}