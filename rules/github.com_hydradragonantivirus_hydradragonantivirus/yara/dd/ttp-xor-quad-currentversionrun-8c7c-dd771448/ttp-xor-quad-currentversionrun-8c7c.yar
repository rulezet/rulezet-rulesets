rule TTP_XOR_QUAD_CurrentVersionRun_8c7c {
  strings:
    $key_8c7c = { df 13 [2] fb 1d [2] d0 31 [2] fe 13 [2] ea 08 [2] e5 12 [2] fb 0f [2] f9 0e [2] e2 08 [2] fe 0f [2] e2 20 }

  condition:
    any of them
}