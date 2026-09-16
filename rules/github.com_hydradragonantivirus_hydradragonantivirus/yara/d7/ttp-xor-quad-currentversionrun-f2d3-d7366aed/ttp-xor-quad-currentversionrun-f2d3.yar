rule TTP_XOR_QUAD_CurrentVersionRun_f2d3 {
  strings:
    $key_f2d3 = { a1 bc [2] 85 b2 [2] ae 9e [2] 80 bc [2] 94 a7 [2] 9b bd [2] 85 a0 [2] 87 a1 [2] 9c a7 [2] 80 a0 [2] 9c 8f }

  condition:
    any of them
}