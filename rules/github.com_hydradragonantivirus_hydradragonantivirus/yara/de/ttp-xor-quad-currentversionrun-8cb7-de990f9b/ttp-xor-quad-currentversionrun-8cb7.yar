rule TTP_XOR_QUAD_CurrentVersionRun_8cb7 {
  strings:
    $key_8cb7 = { df d8 [2] fb d6 [2] d0 fa [2] fe d8 [2] ea c3 [2] e5 d9 [2] fb c4 [2] f9 c5 [2] e2 c3 [2] fe c4 [2] e2 eb }

  condition:
    any of them
}