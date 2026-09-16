rule TTP_XOR_QUAD_CurrentVersionRun_8c09 {
  strings:
    $key_8c09 = { df 66 [2] fb 68 [2] d0 44 [2] fe 66 [2] ea 7d [2] e5 67 [2] fb 7a [2] f9 7b [2] e2 7d [2] fe 7a [2] e2 55 }

  condition:
    any of them
}