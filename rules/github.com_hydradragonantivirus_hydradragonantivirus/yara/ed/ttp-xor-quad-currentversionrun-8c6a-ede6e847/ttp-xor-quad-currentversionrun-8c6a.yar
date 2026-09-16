rule TTP_XOR_QUAD_CurrentVersionRun_8c6a {
  strings:
    $key_8c6a = { df 05 [2] fb 0b [2] d0 27 [2] fe 05 [2] ea 1e [2] e5 04 [2] fb 19 [2] f9 18 [2] e2 1e [2] fe 19 [2] e2 36 }

  condition:
    any of them
}