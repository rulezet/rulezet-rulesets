rule TTP_XOR_QUAD_CurrentVersionRun_1aa7 {
  strings:
    $key_1aa7 = { 49 c8 [2] 6d c6 [2] 46 ea [2] 68 c8 [2] 7c d3 [2] 73 c9 [2] 6d d4 [2] 6f d5 [2] 74 d3 [2] 68 d4 [2] 74 fb }

  condition:
    any of them
}