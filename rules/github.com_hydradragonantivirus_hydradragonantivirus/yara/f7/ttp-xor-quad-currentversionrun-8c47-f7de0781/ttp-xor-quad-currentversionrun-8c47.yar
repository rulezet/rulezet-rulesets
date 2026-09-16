rule TTP_XOR_QUAD_CurrentVersionRun_8c47 {
  strings:
    $key_8c47 = { df 28 [2] fb 26 [2] d0 0a [2] fe 28 [2] ea 33 [2] e5 29 [2] fb 34 [2] f9 35 [2] e2 33 [2] fe 34 [2] e2 1b }

  condition:
    any of them
}