rule TTP_XOR_QUAD_CurrentVersionRun_95b5 {
  strings:
    $key_95b5 = { c6 da [2] e2 d4 [2] c9 f8 [2] e7 da [2] f3 c1 [2] fc db [2] e2 c6 [2] e0 c7 [2] fb c1 [2] e7 c6 [2] fb e9 }

  condition:
    any of them
}