rule TTP_XOR_QUAD_CurrentVersionRun_d387 {
  strings:
    $key_d387 = { 80 e8 [2] a4 e6 [2] 8f ca [2] a1 e8 [2] b5 f3 [2] ba e9 [2] a4 f4 [2] a6 f5 [2] bd f3 [2] a1 f4 [2] bd db }

  condition:
    any of them
}