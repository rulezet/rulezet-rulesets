rule TTP_XOR_QUAD_CurrentVersionRun_8cd6 {
  strings:
    $key_8cd6 = { df b9 [2] fb b7 [2] d0 9b [2] fe b9 [2] ea a2 [2] e5 b8 [2] fb a5 [2] f9 a4 [2] e2 a2 [2] fe a5 [2] e2 8a }

  condition:
    any of them
}