rule TTP_XOR_QUAD_CurrentVersionRun_c0d4 {
  strings:
    $key_c0d4 = { 93 bb [2] b7 b5 [2] 9c 99 [2] b2 bb [2] a6 a0 [2] a9 ba [2] b7 a7 [2] b5 a6 [2] ae a0 [2] b2 a7 [2] ae 88 }

  condition:
    any of them
}