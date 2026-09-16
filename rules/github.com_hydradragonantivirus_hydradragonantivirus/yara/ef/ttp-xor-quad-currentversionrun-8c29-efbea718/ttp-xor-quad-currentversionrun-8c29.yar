rule TTP_XOR_QUAD_CurrentVersionRun_8c29 {
  strings:
    $key_8c29 = { df 46 [2] fb 48 [2] d0 64 [2] fe 46 [2] ea 5d [2] e5 47 [2] fb 5a [2] f9 5b [2] e2 5d [2] fe 5a [2] e2 75 }

  condition:
    any of them
}