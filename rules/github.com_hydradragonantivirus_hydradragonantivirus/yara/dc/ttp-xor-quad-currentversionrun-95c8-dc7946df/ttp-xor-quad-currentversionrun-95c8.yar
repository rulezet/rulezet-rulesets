rule TTP_XOR_QUAD_CurrentVersionRun_95c8 {
  strings:
    $key_95c8 = { c6 a7 [2] e2 a9 [2] c9 85 [2] e7 a7 [2] f3 bc [2] fc a6 [2] e2 bb [2] e0 ba [2] fb bc [2] e7 bb [2] fb 94 }

  condition:
    any of them
}