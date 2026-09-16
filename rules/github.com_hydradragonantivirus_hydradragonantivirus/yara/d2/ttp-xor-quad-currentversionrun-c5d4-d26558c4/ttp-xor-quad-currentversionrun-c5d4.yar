rule TTP_XOR_QUAD_CurrentVersionRun_c5d4 {
  strings:
    $key_c5d4 = { 96 bb [2] b2 b5 [2] 99 99 [2] b7 bb [2] a3 a0 [2] ac ba [2] b2 a7 [2] b0 a6 [2] ab a0 [2] b7 a7 [2] ab 88 }

  condition:
    any of them
}