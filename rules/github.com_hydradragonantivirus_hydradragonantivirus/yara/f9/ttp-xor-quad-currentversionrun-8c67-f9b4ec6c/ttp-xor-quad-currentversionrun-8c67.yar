rule TTP_XOR_QUAD_CurrentVersionRun_8c67 {
  strings:
    $key_8c67 = { df 08 [2] fb 06 [2] d0 2a [2] fe 08 [2] ea 13 [2] e5 09 [2] fb 14 [2] f9 15 [2] e2 13 [2] fe 14 [2] e2 3b }

  condition:
    any of them
}