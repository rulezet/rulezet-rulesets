rule TTP_XOR_QUAD_CurrentVersionRun_d3a5 {
  strings:
    $key_d3a5 = { 80 ca [2] a4 c4 [2] 8f e8 [2] a1 ca [2] b5 d1 [2] ba cb [2] a4 d6 [2] a6 d7 [2] bd d1 [2] a1 d6 [2] bd f9 }

  condition:
    any of them
}