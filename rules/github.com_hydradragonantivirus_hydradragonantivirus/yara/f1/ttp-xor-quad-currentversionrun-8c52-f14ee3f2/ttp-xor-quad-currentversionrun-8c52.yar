rule TTP_XOR_QUAD_CurrentVersionRun_8c52 {
  strings:
    $key_8c52 = { df 3d [2] fb 33 [2] d0 1f [2] fe 3d [2] ea 26 [2] e5 3c [2] fb 21 [2] f9 20 [2] e2 26 [2] fe 21 [2] e2 0e }

  condition:
    any of them
}