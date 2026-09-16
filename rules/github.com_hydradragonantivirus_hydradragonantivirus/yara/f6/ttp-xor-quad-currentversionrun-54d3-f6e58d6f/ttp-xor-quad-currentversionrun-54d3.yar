rule TTP_XOR_QUAD_CurrentVersionRun_54d3 {
  strings:
    $key_54d3 = { 07 bc [2] 23 b2 [2] 08 9e [2] 26 bc [2] 32 a7 [2] 3d bd [2] 23 a0 [2] 21 a1 [2] 3a a7 [2] 26 a0 [2] 3a 8f }

  condition:
    any of them
}