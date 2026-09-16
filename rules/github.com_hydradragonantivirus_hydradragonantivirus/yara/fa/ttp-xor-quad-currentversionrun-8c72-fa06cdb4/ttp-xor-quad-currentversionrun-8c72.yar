rule TTP_XOR_QUAD_CurrentVersionRun_8c72 {
  strings:
    $key_8c72 = { df 1d [2] fb 13 [2] d0 3f [2] fe 1d [2] ea 06 [2] e5 1c [2] fb 01 [2] f9 00 [2] e2 06 [2] fe 01 [2] e2 2e }

  condition:
    any of them
}