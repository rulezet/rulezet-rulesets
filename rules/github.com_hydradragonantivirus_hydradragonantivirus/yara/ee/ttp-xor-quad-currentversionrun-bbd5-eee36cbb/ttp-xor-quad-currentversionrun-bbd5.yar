rule TTP_XOR_QUAD_CurrentVersionRun_bbd5 {
  strings:
    $key_bbd5 = { e8 ba [2] cc b4 [2] e7 98 [2] c9 ba [2] dd a1 [2] d2 bb [2] cc a6 [2] ce a7 [2] d5 a1 [2] c9 a6 [2] d5 89 }

  condition:
    any of them
}