rule TTP_XOR_QUAD_CurrentVersionRun_36d3 {
  strings:
    $key_36d3 = { 65 bc [2] 41 b2 [2] 6a 9e [2] 44 bc [2] 50 a7 [2] 5f bd [2] 41 a0 [2] 43 a1 [2] 58 a7 [2] 44 a0 [2] 58 8f }

  condition:
    any of them
}