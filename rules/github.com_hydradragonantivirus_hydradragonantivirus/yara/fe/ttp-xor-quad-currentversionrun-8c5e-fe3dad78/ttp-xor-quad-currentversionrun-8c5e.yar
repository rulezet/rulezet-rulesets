rule TTP_XOR_QUAD_CurrentVersionRun_8c5e {
  strings:
    $key_8c5e = { df 31 [2] fb 3f [2] d0 13 [2] fe 31 [2] ea 2a [2] e5 30 [2] fb 2d [2] f9 2c [2] e2 2a [2] fe 2d [2] e2 02 }

  condition:
    any of them
}