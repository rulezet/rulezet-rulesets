rule TTP_XOR_QUAD_CurrentVersionRun_8c19 {
  strings:
    $key_8c19 = { df 76 [2] fb 78 [2] d0 54 [2] fe 76 [2] ea 6d [2] e5 77 [2] fb 6a [2] f9 6b [2] e2 6d [2] fe 6a [2] e2 45 }

  condition:
    any of them
}