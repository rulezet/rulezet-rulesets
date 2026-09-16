rule TTP_XOR_QUAD_CurrentVersionRun_8c53 {
  strings:
    $key_8c53 = { df 3c [2] fb 32 [2] d0 1e [2] fe 3c [2] ea 27 [2] e5 3d [2] fb 20 [2] f9 21 [2] e2 27 [2] fe 20 [2] e2 0f }

  condition:
    any of them
}