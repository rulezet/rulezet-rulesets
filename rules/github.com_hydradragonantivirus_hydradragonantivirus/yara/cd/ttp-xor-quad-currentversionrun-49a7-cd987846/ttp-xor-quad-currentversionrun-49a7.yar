rule TTP_XOR_QUAD_CurrentVersionRun_49a7 {
  strings:
    $key_49a7 = { 1a c8 [2] 3e c6 [2] 15 ea [2] 3b c8 [2] 2f d3 [2] 20 c9 [2] 3e d4 [2] 3c d5 [2] 27 d3 [2] 3b d4 [2] 27 fb }

  condition:
    any of them
}