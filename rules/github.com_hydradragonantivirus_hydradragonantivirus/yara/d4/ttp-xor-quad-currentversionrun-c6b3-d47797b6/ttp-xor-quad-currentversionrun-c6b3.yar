rule TTP_XOR_QUAD_CurrentVersionRun_c6b3 {
  strings:
    $key_c6b3 = { 95 dc [2] b1 d2 [2] 9a fe [2] b4 dc [2] a0 c7 [2] af dd [2] b1 c0 [2] b3 c1 [2] a8 c7 [2] b4 c0 [2] a8 ef }

  condition:
    any of them
}