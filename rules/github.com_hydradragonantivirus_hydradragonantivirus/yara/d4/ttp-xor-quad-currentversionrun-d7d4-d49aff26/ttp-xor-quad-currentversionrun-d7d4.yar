rule TTP_XOR_QUAD_CurrentVersionRun_d7d4 {
  strings:
    $key_d7d4 = { 84 bb [2] a0 b5 [2] 8b 99 [2] a5 bb [2] b1 a0 [2] be ba [2] a0 a7 [2] a2 a6 [2] b9 a0 [2] a5 a7 [2] b9 88 }

  condition:
    any of them
}