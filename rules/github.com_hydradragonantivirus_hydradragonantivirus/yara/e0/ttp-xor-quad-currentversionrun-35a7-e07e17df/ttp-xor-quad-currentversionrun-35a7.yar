rule TTP_XOR_QUAD_CurrentVersionRun_35a7 {
  strings:
    $key_35a7 = { 66 c8 [2] 42 c6 [2] 69 ea [2] 47 c8 [2] 53 d3 [2] 5c c9 [2] 42 d4 [2] 40 d5 [2] 5b d3 [2] 47 d4 [2] 5b fb }

  condition:
    any of them
}