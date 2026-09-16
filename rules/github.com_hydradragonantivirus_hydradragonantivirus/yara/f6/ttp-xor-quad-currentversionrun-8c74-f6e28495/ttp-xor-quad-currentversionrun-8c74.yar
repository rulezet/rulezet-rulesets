rule TTP_XOR_QUAD_CurrentVersionRun_8c74 {
  strings:
    $key_8c74 = { df 1b [2] fb 15 [2] d0 39 [2] fe 1b [2] ea 00 [2] e5 1a [2] fb 07 [2] f9 06 [2] e2 00 [2] fe 07 [2] e2 28 }

  condition:
    any of them
}