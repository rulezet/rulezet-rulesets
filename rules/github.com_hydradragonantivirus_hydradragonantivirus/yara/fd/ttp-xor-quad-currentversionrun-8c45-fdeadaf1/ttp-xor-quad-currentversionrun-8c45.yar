rule TTP_XOR_QUAD_CurrentVersionRun_8c45 {
  strings:
    $key_8c45 = { df 2a [2] fb 24 [2] d0 08 [2] fe 2a [2] ea 31 [2] e5 2b [2] fb 36 [2] f9 37 [2] e2 31 [2] fe 36 [2] e2 19 }

  condition:
    any of them
}