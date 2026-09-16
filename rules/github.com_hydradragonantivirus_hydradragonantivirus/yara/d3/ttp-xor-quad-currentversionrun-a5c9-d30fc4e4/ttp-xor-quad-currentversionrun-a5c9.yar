rule TTP_XOR_QUAD_CurrentVersionRun_a5c9 {
  strings:
    $key_a5c9 = { f6 a6 [2] d2 a8 [2] f9 84 [2] d7 a6 [2] c3 bd [2] cc a7 [2] d2 ba [2] d0 bb [2] cb bd [2] d7 ba [2] cb 95 }

  condition:
    any of them
}