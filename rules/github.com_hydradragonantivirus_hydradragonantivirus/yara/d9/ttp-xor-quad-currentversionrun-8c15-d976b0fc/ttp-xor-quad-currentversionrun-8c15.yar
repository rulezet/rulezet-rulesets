rule TTP_XOR_QUAD_CurrentVersionRun_8c15 {
  strings:
    $key_8c15 = { df 7a [2] fb 74 [2] d0 58 [2] fe 7a [2] ea 61 [2] e5 7b [2] fb 66 [2] f9 67 [2] e2 61 [2] fe 66 [2] e2 49 }

  condition:
    any of them
}