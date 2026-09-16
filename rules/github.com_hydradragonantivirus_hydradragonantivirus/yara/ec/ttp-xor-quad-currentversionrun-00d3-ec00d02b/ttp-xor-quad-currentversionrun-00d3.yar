rule TTP_XOR_QUAD_CurrentVersionRun_00d3 {
  strings:
    $key_00d3 = { 53 bc [2] 77 b2 [2] 5c 9e [2] 72 bc [2] 66 a7 [2] 69 bd [2] 77 a0 [2] 75 a1 [2] 6e a7 [2] 72 a0 [2] 6e 8f }

  condition:
    any of them
}