rule TTP_XOR_QUAD_CurrentVersionRun_8c26 {
  strings:
    $key_8c26 = { df 49 [2] fb 47 [2] d0 6b [2] fe 49 [2] ea 52 [2] e5 48 [2] fb 55 [2] f9 54 [2] e2 52 [2] fe 55 [2] e2 7a }

  condition:
    any of them
}