rule TTP_XOR_QUAD_CurrentVersionRun_4da7 {
  strings:
    $key_4da7 = { 1e c8 [2] 3a c6 [2] 11 ea [2] 3f c8 [2] 2b d3 [2] 24 c9 [2] 3a d4 [2] 38 d5 [2] 23 d3 [2] 3f d4 [2] 23 fb }

  condition:
    any of them
}