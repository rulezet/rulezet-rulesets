rule TTP_XOR_QUAD_CurrentVersionRun_cad5 {
  strings:
    $key_cad5 = { 99 ba [2] bd b4 [2] 96 98 [2] b8 ba [2] ac a1 [2] a3 bb [2] bd a6 [2] bf a7 [2] a4 a1 [2] b8 a6 [2] a4 89 }

  condition:
    any of them
}