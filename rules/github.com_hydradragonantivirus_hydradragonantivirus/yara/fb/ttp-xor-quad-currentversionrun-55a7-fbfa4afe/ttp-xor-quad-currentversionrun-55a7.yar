rule TTP_XOR_QUAD_CurrentVersionRun_55a7 {
  strings:
    $key_55a7 = { 06 c8 [2] 22 c6 [2] 09 ea [2] 27 c8 [2] 33 d3 [2] 3c c9 [2] 22 d4 [2] 20 d5 [2] 3b d3 [2] 27 d4 [2] 3b fb }

  condition:
    any of them
}