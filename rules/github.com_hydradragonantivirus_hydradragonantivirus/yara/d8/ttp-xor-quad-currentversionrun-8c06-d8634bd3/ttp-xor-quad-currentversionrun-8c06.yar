rule TTP_XOR_QUAD_CurrentVersionRun_8c06 {
  strings:
    $key_8c06 = { df 69 [2] fb 67 [2] d0 4b [2] fe 69 [2] ea 72 [2] e5 68 [2] fb 75 [2] f9 74 [2] e2 72 [2] fe 75 [2] e2 5a }

  condition:
    any of them
}