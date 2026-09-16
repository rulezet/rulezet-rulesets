rule TTP_XOR_QUAD_CurrentVersionRun_34d3 {
  strings:
    $key_34d3 = { 67 bc [2] 43 b2 [2] 68 9e [2] 46 bc [2] 52 a7 [2] 5d bd [2] 43 a0 [2] 41 a1 [2] 5a a7 [2] 46 a0 [2] 5a 8f }

  condition:
    any of them
}