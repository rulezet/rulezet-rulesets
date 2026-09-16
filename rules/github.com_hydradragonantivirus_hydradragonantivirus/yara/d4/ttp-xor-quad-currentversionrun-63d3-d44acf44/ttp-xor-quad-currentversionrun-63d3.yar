rule TTP_XOR_QUAD_CurrentVersionRun_63d3 {
  strings:
    $key_63d3 = { 30 bc [2] 14 b2 [2] 3f 9e [2] 11 bc [2] 05 a7 [2] 0a bd [2] 14 a0 [2] 16 a1 [2] 0d a7 [2] 11 a0 [2] 0d 8f }

  condition:
    any of them
}