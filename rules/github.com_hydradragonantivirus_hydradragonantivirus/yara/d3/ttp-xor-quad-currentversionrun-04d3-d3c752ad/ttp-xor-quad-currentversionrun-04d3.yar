rule TTP_XOR_QUAD_CurrentVersionRun_04d3 {
  strings:
    $key_04d3 = { 57 bc [2] 73 b2 [2] 58 9e [2] 76 bc [2] 62 a7 [2] 6d bd [2] 73 a0 [2] 71 a1 [2] 6a a7 [2] 76 a0 [2] 6a 8f }

  condition:
    any of them
}