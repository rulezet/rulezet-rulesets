rule TTP_XOR_QUAD_CurrentVersionRun_daa7 {
  strings:
    $key_daa7 = { 89 c8 [2] ad c6 [2] 86 ea [2] a8 c8 [2] bc d3 [2] b3 c9 [2] ad d4 [2] af d5 [2] b4 d3 [2] a8 d4 [2] b4 fb }

  condition:
    any of them
}