rule TTP_XOR_QUAD_CurrentVersionRun_c7c9 {
  strings:
    $key_c7c9 = { 94 a6 [2] b0 a8 [2] 9b 84 [2] b5 a6 [2] a1 bd [2] ae a7 [2] b0 ba [2] b2 bb [2] a9 bd [2] b5 ba [2] a9 95 }

  condition:
    any of them
}