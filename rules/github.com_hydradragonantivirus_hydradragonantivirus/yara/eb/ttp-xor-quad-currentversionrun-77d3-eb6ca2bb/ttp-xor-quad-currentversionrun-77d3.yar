rule TTP_XOR_QUAD_CurrentVersionRun_77d3 {
  strings:
    $key_77d3 = { 24 bc [2] 00 b2 [2] 2b 9e [2] 05 bc [2] 11 a7 [2] 1e bd [2] 00 a0 [2] 02 a1 [2] 19 a7 [2] 05 a0 [2] 19 8f }

  condition:
    any of them
}