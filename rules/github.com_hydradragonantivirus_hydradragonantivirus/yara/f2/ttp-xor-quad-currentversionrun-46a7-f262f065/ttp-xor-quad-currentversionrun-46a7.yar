rule TTP_XOR_QUAD_CurrentVersionRun_46a7 {
  strings:
    $key_46a7 = { 15 c8 [2] 31 c6 [2] 1a ea [2] 34 c8 [2] 20 d3 [2] 2f c9 [2] 31 d4 [2] 33 d5 [2] 28 d3 [2] 34 d4 [2] 28 fb }

  condition:
    any of them
}