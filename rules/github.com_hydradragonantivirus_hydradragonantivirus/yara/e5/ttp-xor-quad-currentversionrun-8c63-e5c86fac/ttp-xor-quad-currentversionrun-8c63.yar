rule TTP_XOR_QUAD_CurrentVersionRun_8c63 {
  strings:
    $key_8c63 = { df 0c [2] fb 02 [2] d0 2e [2] fe 0c [2] ea 17 [2] e5 0d [2] fb 10 [2] f9 11 [2] e2 17 [2] fe 10 [2] e2 3f }

  condition:
    any of them
}