rule TTP_XOR_QUAD_CurrentVersionRun_8c65 {
  strings:
    $key_8c65 = { df 0a [2] fb 04 [2] d0 28 [2] fe 0a [2] ea 11 [2] e5 0b [2] fb 16 [2] f9 17 [2] e2 11 [2] fe 16 [2] e2 39 }

  condition:
    any of them
}