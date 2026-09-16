rule TTP_XOR_QUAD_CurrentVersionRun_36a7 {
  strings:
    $key_36a7 = { 65 c8 [2] 41 c6 [2] 6a ea [2] 44 c8 [2] 50 d3 [2] 5f c9 [2] 41 d4 [2] 43 d5 [2] 58 d3 [2] 44 d4 [2] 58 fb }

  condition:
    any of them
}