rule TTP_XOR_QUAD_CurrentVersionRun_03a7 {
  strings:
    $key_03a7 = { 50 c8 [2] 74 c6 [2] 5f ea [2] 71 c8 [2] 65 d3 [2] 6a c9 [2] 74 d4 [2] 76 d5 [2] 6d d3 [2] 71 d4 [2] 6d fb }

  condition:
    any of them
}