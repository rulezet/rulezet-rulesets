rule TTP_XOR_QUAD_CurrentVersionRun_01d3 {
  strings:
    $key_01d3 = { 52 bc [2] 76 b2 [2] 5d 9e [2] 73 bc [2] 67 a7 [2] 68 bd [2] 76 a0 [2] 74 a1 [2] 6f a7 [2] 73 a0 [2] 6f 8f }

  condition:
    any of them
}