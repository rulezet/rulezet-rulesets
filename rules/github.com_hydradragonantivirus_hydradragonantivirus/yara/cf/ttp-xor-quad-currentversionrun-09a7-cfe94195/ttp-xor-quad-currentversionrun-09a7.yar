rule TTP_XOR_QUAD_CurrentVersionRun_09a7 {
  strings:
    $key_09a7 = { 5a c8 [2] 7e c6 [2] 55 ea [2] 7b c8 [2] 6f d3 [2] 60 c9 [2] 7e d4 [2] 7c d5 [2] 67 d3 [2] 7b d4 [2] 67 fb }

  condition:
    any of them
}