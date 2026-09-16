rule TTP_XOR_QUAD_CurrentVersionRun_33d3 {
  strings:
    $key_33d3 = { 60 bc [2] 44 b2 [2] 6f 9e [2] 41 bc [2] 55 a7 [2] 5a bd [2] 44 a0 [2] 46 a1 [2] 5d a7 [2] 41 a0 [2] 5d 8f }

  condition:
    any of them
}