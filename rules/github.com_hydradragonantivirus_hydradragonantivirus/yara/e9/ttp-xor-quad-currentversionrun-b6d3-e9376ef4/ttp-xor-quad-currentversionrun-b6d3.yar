rule TTP_XOR_QUAD_CurrentVersionRun_b6d3 {
  strings:
    $key_b6d3 = { e5 bc [2] c1 b2 [2] ea 9e [2] c4 bc [2] d0 a7 [2] df bd [2] c1 a0 [2] c3 a1 [2] d8 a7 [2] c4 a0 [2] d8 8f }

  condition:
    any of them
}