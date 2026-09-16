rule TTP_XOR_QUAD_CurrentVersionRun_60d3 {
  strings:
    $key_60d3 = { 33 bc [2] 17 b2 [2] 3c 9e [2] 12 bc [2] 06 a7 [2] 09 bd [2] 17 a0 [2] 15 a1 [2] 0e a7 [2] 12 a0 [2] 0e 8f }

  condition:
    any of them
}