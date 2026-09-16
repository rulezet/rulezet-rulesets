rule TTP_XOR_QUAD_CurrentVersionRun_c6c8 {
  strings:
    $key_c6c8 = { 95 a7 [2] b1 a9 [2] 9a 85 [2] b4 a7 [2] a0 bc [2] af a6 [2] b1 bb [2] b3 ba [2] a8 bc [2] b4 bb [2] a8 94 }

  condition:
    any of them
}