rule TTP_XOR_QUAD_CurrentVersionRun_c8c8 {
  strings:
    $key_c8c8 = { 9b a7 [2] bf a9 [2] 94 85 [2] ba a7 [2] ae bc [2] a1 a6 [2] bf bb [2] bd ba [2] a6 bc [2] ba bb [2] a6 94 }

  condition:
    any of them
}