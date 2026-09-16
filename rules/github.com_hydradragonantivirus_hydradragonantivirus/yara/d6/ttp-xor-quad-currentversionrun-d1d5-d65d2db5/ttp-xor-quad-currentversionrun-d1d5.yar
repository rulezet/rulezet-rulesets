rule TTP_XOR_QUAD_CurrentVersionRun_d1d5 {
  strings:
    $key_d1d5 = { 82 ba [2] a6 b4 [2] 8d 98 [2] a3 ba [2] b7 a1 [2] b8 bb [2] a6 a6 [2] a4 a7 [2] bf a1 [2] a3 a6 [2] bf 89 }

  condition:
    any of them
}