rule TTP_XOR_QUAD_CurrentVersionRun_d4b5 {
  strings:
    $key_d4b5 = { 87 da [2] a3 d4 [2] 88 f8 [2] a6 da [2] b2 c1 [2] bd db [2] a3 c6 [2] a1 c7 [2] ba c1 [2] a6 c6 [2] ba e9 }

  condition:
    any of them
}