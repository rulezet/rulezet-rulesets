rule TTP_XOR_QUAD_CurrentVersionRun_d3a8 {
  strings:
    $key_d3a8 = { 80 c7 [2] a4 c9 [2] 8f e5 [2] a1 c7 [2] b5 dc [2] ba c6 [2] a4 db [2] a6 da [2] bd dc [2] a1 db [2] bd f4 }

  condition:
    any of them
}