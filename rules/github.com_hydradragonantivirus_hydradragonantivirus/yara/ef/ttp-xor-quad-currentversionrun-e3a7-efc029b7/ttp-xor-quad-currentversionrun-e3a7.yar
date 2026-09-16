rule TTP_XOR_QUAD_CurrentVersionRun_e3a7 {
  strings:
    $key_e3a7 = { b0 c8 [2] 94 c6 [2] bf ea [2] 91 c8 [2] 85 d3 [2] 8a c9 [2] 94 d4 [2] 96 d5 [2] 8d d3 [2] 91 d4 [2] 8d fb }

  condition:
    any of them
}