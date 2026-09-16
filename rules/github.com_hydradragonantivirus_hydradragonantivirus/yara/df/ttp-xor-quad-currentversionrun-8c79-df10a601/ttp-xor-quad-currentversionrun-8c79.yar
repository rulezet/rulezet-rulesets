rule TTP_XOR_QUAD_CurrentVersionRun_8c79 {
  strings:
    $key_8c79 = { df 16 [2] fb 18 [2] d0 34 [2] fe 16 [2] ea 0d [2] e5 17 [2] fb 0a [2] f9 0b [2] e2 0d [2] fe 0a [2] e2 25 }

  condition:
    any of them
}