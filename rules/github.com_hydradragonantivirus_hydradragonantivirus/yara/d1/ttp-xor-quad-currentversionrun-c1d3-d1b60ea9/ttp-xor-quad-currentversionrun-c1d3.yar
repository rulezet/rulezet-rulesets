rule TTP_XOR_QUAD_CurrentVersionRun_c1d3 {
  strings:
    $key_c1d3 = { 92 bc [2] b6 b2 [2] 9d 9e [2] b3 bc [2] a7 a7 [2] a8 bd [2] b6 a0 [2] b4 a1 [2] af a7 [2] b3 a0 [2] af 8f }

  condition:
    any of them
}