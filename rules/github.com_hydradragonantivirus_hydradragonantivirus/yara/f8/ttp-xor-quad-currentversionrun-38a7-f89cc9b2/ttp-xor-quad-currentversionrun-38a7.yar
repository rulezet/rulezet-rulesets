rule TTP_XOR_QUAD_CurrentVersionRun_38a7 {
  strings:
    $key_38a7 = { 6b c8 [2] 4f c6 [2] 64 ea [2] 4a c8 [2] 5e d3 [2] 51 c9 [2] 4f d4 [2] 4d d5 [2] 56 d3 [2] 4a d4 [2] 56 fb }

  condition:
    any of them
}