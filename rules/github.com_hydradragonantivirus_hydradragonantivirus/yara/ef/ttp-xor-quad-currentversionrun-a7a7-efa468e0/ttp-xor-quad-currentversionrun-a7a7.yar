rule TTP_XOR_QUAD_CurrentVersionRun_a7a7 {
  strings:
    $key_a7a7 = { f4 c8 [2] d0 c6 [2] fb ea [2] d5 c8 [2] c1 d3 [2] ce c9 [2] d0 d4 [2] d2 d5 [2] c9 d3 [2] d5 d4 [2] c9 fb }

  condition:
    any of them
}