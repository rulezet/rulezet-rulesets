rule TTP_XOR_QUAD_CurrentVersionRun_c7d4 {
  strings:
    $key_c7d4 = { 94 bb [2] b0 b5 [2] 9b 99 [2] b5 bb [2] a1 a0 [2] ae ba [2] b0 a7 [2] b2 a6 [2] a9 a0 [2] b5 a7 [2] a9 88 }

  condition:
    any of them
}