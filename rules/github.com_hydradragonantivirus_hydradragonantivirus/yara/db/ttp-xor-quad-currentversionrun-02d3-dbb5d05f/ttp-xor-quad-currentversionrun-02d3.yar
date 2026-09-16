rule TTP_XOR_QUAD_CurrentVersionRun_02d3 {
  strings:
    $key_02d3 = { 51 bc [2] 75 b2 [2] 5e 9e [2] 70 bc [2] 64 a7 [2] 6b bd [2] 75 a0 [2] 77 a1 [2] 6c a7 [2] 70 a0 [2] 6c 8f }

  condition:
    any of them
}