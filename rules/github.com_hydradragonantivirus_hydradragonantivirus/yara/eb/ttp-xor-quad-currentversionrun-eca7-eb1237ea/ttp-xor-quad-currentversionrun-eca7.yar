rule TTP_XOR_QUAD_CurrentVersionRun_eca7 {
  strings:
    $key_eca7 = { bf c8 [2] 9b c6 [2] b0 ea [2] 9e c8 [2] 8a d3 [2] 85 c9 [2] 9b d4 [2] 99 d5 [2] 82 d3 [2] 9e d4 [2] 82 fb }

  condition:
    any of them
}