rule TTP_XOR_QUAD_CurrentVersionRun_8ca2 {
  strings:
    $key_8ca2 = { df cd [2] fb c3 [2] d0 ef [2] fe cd [2] ea d6 [2] e5 cc [2] fb d1 [2] f9 d0 [2] e2 d6 [2] fe d1 [2] e2 fe }

  condition:
    any of them
}