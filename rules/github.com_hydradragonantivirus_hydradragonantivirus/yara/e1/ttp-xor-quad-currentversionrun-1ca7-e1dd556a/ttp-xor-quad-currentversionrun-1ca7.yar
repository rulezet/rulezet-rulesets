rule TTP_XOR_QUAD_CurrentVersionRun_1ca7 {
  strings:
    $key_1ca7 = { 4f c8 [2] 6b c6 [2] 40 ea [2] 6e c8 [2] 7a d3 [2] 75 c9 [2] 6b d4 [2] 69 d5 [2] 72 d3 [2] 6e d4 [2] 72 fb }

  condition:
    any of them
}