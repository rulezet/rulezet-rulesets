rule TTP_XOR_QUAD_CurrentVersionRun_75a7 {
  strings:
    $key_75a7 = { 26 c8 [2] 02 c6 [2] 29 ea [2] 07 c8 [2] 13 d3 [2] 1c c9 [2] 02 d4 [2] 00 d5 [2] 1b d3 [2] 07 d4 [2] 1b fb }

  condition:
    any of them
}