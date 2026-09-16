rule TTP_XOR_QUAD_CurrentVersionRun_95c9 {
  strings:
    $key_95c9 = { c6 a6 [2] e2 a8 [2] c9 84 [2] e7 a6 [2] f3 bd [2] fc a7 [2] e2 ba [2] e0 bb [2] fb bd [2] e7 ba [2] fb 95 }

  condition:
    any of them
}