rule TTP_XOR_QUAD_CurrentVersionRun_7ca7 {
  strings:
    $key_7ca7 = { 2f c8 [2] 0b c6 [2] 20 ea [2] 0e c8 [2] 1a d3 [2] 15 c9 [2] 0b d4 [2] 09 d5 [2] 12 d3 [2] 0e d4 [2] 12 fb }

  condition:
    any of them
}