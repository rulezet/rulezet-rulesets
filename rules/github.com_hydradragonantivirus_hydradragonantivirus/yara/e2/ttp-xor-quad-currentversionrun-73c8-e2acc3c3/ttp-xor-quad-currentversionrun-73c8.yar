rule TTP_XOR_QUAD_CurrentVersionRun_73c8 {
  strings:
    $key_73c8 = { 20 a7 [2] 04 a9 [2] 2f 85 [2] 01 a7 [2] 15 bc [2] 1a a6 [2] 04 bb [2] 06 ba [2] 1d bc [2] 01 bb [2] 1d 94 }

  condition:
    any of them
}