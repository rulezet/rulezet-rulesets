rule TTP_XOR_QUAD_CurrentVersionRun_8ca4 {
  strings:
    $key_8ca4 = { df cb [2] fb c5 [2] d0 e9 [2] fe cb [2] ea d0 [2] e5 ca [2] fb d7 [2] f9 d6 [2] e2 d0 [2] fe d7 [2] e2 f8 }

  condition:
    any of them
}