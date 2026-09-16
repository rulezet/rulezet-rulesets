rule TTP_XOR_QUAD_CurrentVersionRun_d4c7 {
  strings:
    $key_d4c7 = { 87 a8 [2] a3 a6 [2] 88 8a [2] a6 a8 [2] b2 b3 [2] bd a9 [2] a3 b4 [2] a1 b5 [2] ba b3 [2] a6 b4 [2] ba 9b }

  condition:
    any of them
}