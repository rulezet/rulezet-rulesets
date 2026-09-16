rule TTP_XOR_QUAD_CurrentVersionRun_c3a7 {
  strings:
    $key_c3a7 = { 90 c8 [2] b4 c6 [2] 9f ea [2] b1 c8 [2] a5 d3 [2] aa c9 [2] b4 d4 [2] b6 d5 [2] ad d3 [2] b1 d4 [2] ad fb }

  condition:
    any of them
}