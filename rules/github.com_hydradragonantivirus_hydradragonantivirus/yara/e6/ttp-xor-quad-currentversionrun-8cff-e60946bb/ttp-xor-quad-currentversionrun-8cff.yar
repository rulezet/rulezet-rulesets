rule TTP_XOR_QUAD_CurrentVersionRun_8cff {
  strings:
    $key_8cff = { df 90 [2] fb 9e [2] d0 b2 [2] fe 90 [2] ea 8b [2] e5 91 [2] fb 8c [2] f9 8d [2] e2 8b [2] fe 8c [2] e2 a3 }

  condition:
    any of them
}