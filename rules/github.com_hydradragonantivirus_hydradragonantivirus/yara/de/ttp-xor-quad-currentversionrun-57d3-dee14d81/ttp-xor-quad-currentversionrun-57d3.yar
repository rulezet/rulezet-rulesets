rule TTP_XOR_QUAD_CurrentVersionRun_57d3 {
  strings:
    $key_57d3 = { 04 bc [2] 20 b2 [2] 0b 9e [2] 25 bc [2] 31 a7 [2] 3e bd [2] 20 a0 [2] 22 a1 [2] 39 a7 [2] 25 a0 [2] 39 8f }

  condition:
    any of them
}