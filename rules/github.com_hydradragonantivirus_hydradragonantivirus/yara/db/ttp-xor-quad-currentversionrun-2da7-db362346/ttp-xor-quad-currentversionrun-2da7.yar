rule TTP_XOR_QUAD_CurrentVersionRun_2da7 {
  strings:
    $key_2da7 = { 7e c8 [2] 5a c6 [2] 71 ea [2] 5f c8 [2] 4b d3 [2] 44 c9 [2] 5a d4 [2] 58 d5 [2] 43 d3 [2] 5f d4 [2] 43 fb }

  condition:
    any of them
}