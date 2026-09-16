rule TTP_XOR_QUAD_CurrentVersionRun_7da7 {
  strings:
    $key_7da7 = { 2e c8 [2] 0a c6 [2] 21 ea [2] 0f c8 [2] 1b d3 [2] 14 c9 [2] 0a d4 [2] 08 d5 [2] 13 d3 [2] 0f d4 [2] 13 fb }

  condition:
    any of them
}