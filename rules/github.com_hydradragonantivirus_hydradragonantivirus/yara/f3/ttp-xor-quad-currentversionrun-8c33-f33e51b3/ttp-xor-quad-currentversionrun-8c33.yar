rule TTP_XOR_QUAD_CurrentVersionRun_8c33 {
  strings:
    $key_8c33 = { df 5c [2] fb 52 [2] d0 7e [2] fe 5c [2] ea 47 [2] e5 5d [2] fb 40 [2] f9 41 [2] e2 47 [2] fe 40 [2] e2 6f }

  condition:
    any of them
}