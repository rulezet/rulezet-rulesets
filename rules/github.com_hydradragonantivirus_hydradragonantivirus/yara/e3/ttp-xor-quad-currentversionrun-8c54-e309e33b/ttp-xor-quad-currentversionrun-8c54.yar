rule TTP_XOR_QUAD_CurrentVersionRun_8c54 {
  strings:
    $key_8c54 = { df 3b [2] fb 35 [2] d0 19 [2] fe 3b [2] ea 20 [2] e5 3a [2] fb 27 [2] f9 26 [2] e2 20 [2] fe 27 [2] e2 08 }

  condition:
    any of them
}