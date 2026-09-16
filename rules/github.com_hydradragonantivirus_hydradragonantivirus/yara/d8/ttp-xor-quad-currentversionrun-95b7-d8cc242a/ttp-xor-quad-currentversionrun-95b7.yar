rule TTP_XOR_QUAD_CurrentVersionRun_95b7 {
  strings:
    $key_95b7 = { c6 d8 [2] e2 d6 [2] c9 fa [2] e7 d8 [2] f3 c3 [2] fc d9 [2] e2 c4 [2] e0 c5 [2] fb c3 [2] e7 c4 [2] fb eb }

  condition:
    any of them
}