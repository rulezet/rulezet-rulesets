rule TTP_XOR_QUAD_CurrentVersionRun_d2a7 {
  strings:
    $key_d2a7 = { 81 c8 [2] a5 c6 [2] 8e ea [2] a0 c8 [2] b4 d3 [2] bb c9 [2] a5 d4 [2] a7 d5 [2] bc d3 [2] a0 d4 [2] bc fb }

  condition:
    any of them
}