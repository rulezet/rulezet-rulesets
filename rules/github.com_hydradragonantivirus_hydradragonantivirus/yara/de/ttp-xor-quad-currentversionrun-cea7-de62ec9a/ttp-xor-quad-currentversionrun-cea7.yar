rule TTP_XOR_QUAD_CurrentVersionRun_cea7 {
  strings:
    $key_cea7 = { 9d c8 [2] b9 c6 [2] 92 ea [2] bc c8 [2] a8 d3 [2] a7 c9 [2] b9 d4 [2] bb d5 [2] a0 d3 [2] bc d4 [2] a0 fb }

  condition:
    any of them
}