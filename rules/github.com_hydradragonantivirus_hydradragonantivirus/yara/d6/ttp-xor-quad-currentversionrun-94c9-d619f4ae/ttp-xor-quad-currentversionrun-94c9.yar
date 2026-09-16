rule TTP_XOR_QUAD_CurrentVersionRun_94c9 {
  strings:
    $key_94c9 = { c7 a6 [2] e3 a8 [2] c8 84 [2] e6 a6 [2] f2 bd [2] fd a7 [2] e3 ba [2] e1 bb [2] fa bd [2] e6 ba [2] fa 95 }

  condition:
    any of them
}