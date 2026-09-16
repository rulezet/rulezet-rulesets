rule TTP_XOR_QUAD_CurrentVersionRun_bbc8 {
  strings:
    $key_bbc8 = { e8 a7 [2] cc a9 [2] e7 85 [2] c9 a7 [2] dd bc [2] d2 a6 [2] cc bb [2] ce ba [2] d5 bc [2] c9 bb [2] d5 94 }

  condition:
    any of them
}