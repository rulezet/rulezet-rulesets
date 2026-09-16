rule TTP_XOR_QUAD_CurrentVersionRun_e8a7 {
  strings:
    $key_e8a7 = { bb c8 [2] 9f c6 [2] b4 ea [2] 9a c8 [2] 8e d3 [2] 81 c9 [2] 9f d4 [2] 9d d5 [2] 86 d3 [2] 9a d4 [2] 86 fb }

  condition:
    any of them
}