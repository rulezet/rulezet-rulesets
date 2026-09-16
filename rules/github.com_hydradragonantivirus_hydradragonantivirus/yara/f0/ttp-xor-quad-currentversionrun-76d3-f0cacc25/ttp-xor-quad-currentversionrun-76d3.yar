rule TTP_XOR_QUAD_CurrentVersionRun_76d3 {
  strings:
    $key_76d3 = { 25 bc [2] 01 b2 [2] 2a 9e [2] 04 bc [2] 10 a7 [2] 1f bd [2] 01 a0 [2] 03 a1 [2] 18 a7 [2] 04 a0 [2] 18 8f }

  condition:
    any of them
}