rule TTP_XOR_QUAD_CurrentVersionRun_8c99 {
  strings:
    $key_8c99 = { df f6 [2] fb f8 [2] d0 d4 [2] fe f6 [2] ea ed [2] e5 f7 [2] fb ea [2] f9 eb [2] e2 ed [2] fe ea [2] e2 c5 }

  condition:
    any of them
}