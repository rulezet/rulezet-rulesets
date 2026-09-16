rule TTP_XOR_QUAD_CurrentVersionRun_41a7 {
  strings:
    $key_41a7 = { 12 c8 [2] 36 c6 [2] 1d ea [2] 33 c8 [2] 27 d3 [2] 28 c9 [2] 36 d4 [2] 34 d5 [2] 2f d3 [2] 33 d4 [2] 2f fb }

  condition:
    any of them
}