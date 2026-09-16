rule TTP_XOR_QUAD_CurrentVersionRun_95a6 {
  strings:
    $key_95a6 = { c6 c9 [2] e2 c7 [2] c9 eb [2] e7 c9 [2] f3 d2 [2] fc c8 [2] e2 d5 [2] e0 d4 [2] fb d2 [2] e7 d5 [2] fb fa }

  condition:
    any of them
}