rule TTP_XOR_QUAD_CurrentVersionRun_43d3 {
  strings:
    $key_43d3 = { 10 bc [2] 34 b2 [2] 1f 9e [2] 31 bc [2] 25 a7 [2] 2a bd [2] 34 a0 [2] 36 a1 [2] 2d a7 [2] 31 a0 [2] 2d 8f }

  condition:
    any of them
}