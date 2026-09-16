rule TTP_XOR_QUAD_CurrentVersionRun_d3a4 {
  strings:
    $key_d3a4 = { 80 cb [2] a4 c5 [2] 8f e9 [2] a1 cb [2] b5 d0 [2] ba ca [2] a4 d7 [2] a6 d6 [2] bd d0 [2] a1 d7 [2] bd f8 }

  condition:
    any of them
}