rule TTP_XOR_QUAD_CurrentVersionRun_d3b8 {
  strings:
    $key_d3b8 = { 80 d7 [2] a4 d9 [2] 8f f5 [2] a1 d7 [2] b5 cc [2] ba d6 [2] a4 cb [2] a6 ca [2] bd cc [2] a1 cb [2] bd e4 }

  condition:
    any of them
}