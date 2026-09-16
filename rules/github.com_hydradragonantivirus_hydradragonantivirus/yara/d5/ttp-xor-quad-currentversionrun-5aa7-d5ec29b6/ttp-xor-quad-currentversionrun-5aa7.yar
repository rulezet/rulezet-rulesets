rule TTP_XOR_QUAD_CurrentVersionRun_5aa7 {
  strings:
    $key_5aa7 = { 09 c8 [2] 2d c6 [2] 06 ea [2] 28 c8 [2] 3c d3 [2] 33 c9 [2] 2d d4 [2] 2f d5 [2] 34 d3 [2] 28 d4 [2] 34 fb }

  condition:
    any of them
}