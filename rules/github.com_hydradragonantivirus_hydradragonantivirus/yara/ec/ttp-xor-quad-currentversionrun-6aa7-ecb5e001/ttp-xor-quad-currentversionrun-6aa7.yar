rule TTP_XOR_QUAD_CurrentVersionRun_6aa7 {
  strings:
    $key_6aa7 = { 39 c8 [2] 1d c6 [2] 36 ea [2] 18 c8 [2] 0c d3 [2] 03 c9 [2] 1d d4 [2] 1f d5 [2] 04 d3 [2] 18 d4 [2] 04 fb }

  condition:
    any of them
}