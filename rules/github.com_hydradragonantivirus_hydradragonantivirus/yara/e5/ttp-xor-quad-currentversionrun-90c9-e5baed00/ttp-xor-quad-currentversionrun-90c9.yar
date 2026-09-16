rule TTP_XOR_QUAD_CurrentVersionRun_90c9 {
  strings:
    $key_90c9 = { c3 a6 [2] e7 a8 [2] cc 84 [2] e2 a6 [2] f6 bd [2] f9 a7 [2] e7 ba [2] e5 bb [2] fe bd [2] e2 ba [2] fe 95 }

  condition:
    any of them
}