rule TTP_XOR_QUAD_CurrentVersionRun_b1a7 {
  strings:
    $key_b1a7 = { e2 c8 [2] c6 c6 [2] ed ea [2] c3 c8 [2] d7 d3 [2] d8 c9 [2] c6 d4 [2] c4 d5 [2] df d3 [2] c3 d4 [2] df fb }

  condition:
    any of them
}