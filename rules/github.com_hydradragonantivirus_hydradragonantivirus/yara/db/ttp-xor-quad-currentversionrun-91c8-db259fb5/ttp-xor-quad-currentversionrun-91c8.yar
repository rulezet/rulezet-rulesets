rule TTP_XOR_QUAD_CurrentVersionRun_91c8 {
  strings:
    $key_91c8 = { c2 a7 [2] e6 a9 [2] cd 85 [2] e3 a7 [2] f7 bc [2] f8 a6 [2] e6 bb [2] e4 ba [2] ff bc [2] e3 bb [2] ff 94 }

  condition:
    any of them
}