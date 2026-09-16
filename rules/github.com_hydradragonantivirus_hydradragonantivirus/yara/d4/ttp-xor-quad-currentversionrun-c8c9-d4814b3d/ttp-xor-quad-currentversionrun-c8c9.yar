rule TTP_XOR_QUAD_CurrentVersionRun_c8c9 {
  strings:
    $key_c8c9 = { 9b a6 [2] bf a8 [2] 94 84 [2] ba a6 [2] ae bd [2] a1 a7 [2] bf ba [2] bd bb [2] a6 bd [2] ba ba [2] a6 95 }

  condition:
    any of them
}