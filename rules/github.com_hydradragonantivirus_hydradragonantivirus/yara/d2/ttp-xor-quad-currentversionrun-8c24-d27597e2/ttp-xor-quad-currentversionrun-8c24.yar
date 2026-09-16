rule TTP_XOR_QUAD_CurrentVersionRun_8c24 {
  strings:
    $key_8c24 = { df 4b [2] fb 45 [2] d0 69 [2] fe 4b [2] ea 50 [2] e5 4a [2] fb 57 [2] f9 56 [2] e2 50 [2] fe 57 [2] e2 78 }

  condition:
    any of them
}