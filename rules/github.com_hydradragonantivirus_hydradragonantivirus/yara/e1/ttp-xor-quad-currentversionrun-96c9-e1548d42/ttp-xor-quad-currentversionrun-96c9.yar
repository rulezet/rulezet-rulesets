rule TTP_XOR_QUAD_CurrentVersionRun_96c9 {
  strings:
    $key_96c9 = { c5 a6 [2] e1 a8 [2] ca 84 [2] e4 a6 [2] f0 bd [2] ff a7 [2] e1 ba [2] e3 bb [2] f8 bd [2] e4 ba [2] f8 95 }

  condition:
    any of them
}