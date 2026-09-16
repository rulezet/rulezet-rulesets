rule TTP_XOR_QUAD_CurrentVersionRun_71d3 {
  strings:
    $key_71d3 = { 22 bc [2] 06 b2 [2] 2d 9e [2] 03 bc [2] 17 a7 [2] 18 bd [2] 06 a0 [2] 04 a1 [2] 1f a7 [2] 03 a0 [2] 1f 8f }

  condition:
    any of them
}