rule TTP_XOR_QUAD_CurrentVersionRun_8cea {
  strings:
    $key_8cea = { df 85 [2] fb 8b [2] d0 a7 [2] fe 85 [2] ea 9e [2] e5 84 [2] fb 99 [2] f9 98 [2] e2 9e [2] fe 99 [2] e2 b6 }

  condition:
    any of them
}