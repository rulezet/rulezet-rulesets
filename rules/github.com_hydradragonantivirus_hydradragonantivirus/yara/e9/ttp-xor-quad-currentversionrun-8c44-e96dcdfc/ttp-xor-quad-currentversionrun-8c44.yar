rule TTP_XOR_QUAD_CurrentVersionRun_8c44 {
  strings:
    $key_8c44 = { df 2b [2] fb 25 [2] d0 09 [2] fe 2b [2] ea 30 [2] e5 2a [2] fb 37 [2] f9 36 [2] e2 30 [2] fe 37 [2] e2 18 }

  condition:
    any of them
}