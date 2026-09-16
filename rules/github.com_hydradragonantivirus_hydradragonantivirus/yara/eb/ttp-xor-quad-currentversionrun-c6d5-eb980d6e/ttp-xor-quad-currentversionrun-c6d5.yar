rule TTP_XOR_QUAD_CurrentVersionRun_c6d5 {
  strings:
    $key_c6d5 = { 95 ba [2] b1 b4 [2] 9a 98 [2] b4 ba [2] a0 a1 [2] af bb [2] b1 a6 [2] b3 a7 [2] a8 a1 [2] b4 a6 [2] a8 89 }

  condition:
    any of them
}