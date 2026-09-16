rule TTP_XOR_QUAD_CurrentVersionRun_07a7 {
  strings:
    $key_07a7 = { 54 c8 [2] 70 c6 [2] 5b ea [2] 75 c8 [2] 61 d3 [2] 6e c9 [2] 70 d4 [2] 72 d5 [2] 69 d3 [2] 75 d4 [2] 69 fb }

  condition:
    any of them
}