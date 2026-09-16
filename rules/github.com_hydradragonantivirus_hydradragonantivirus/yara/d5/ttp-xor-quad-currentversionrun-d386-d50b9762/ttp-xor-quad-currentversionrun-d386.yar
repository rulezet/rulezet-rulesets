rule TTP_XOR_QUAD_CurrentVersionRun_d386 {
  strings:
    $key_d386 = { 80 e9 [2] a4 e7 [2] 8f cb [2] a1 e9 [2] b5 f2 [2] ba e8 [2] a4 f5 [2] a6 f4 [2] bd f2 [2] a1 f5 [2] bd da }

  condition:
    any of them
}