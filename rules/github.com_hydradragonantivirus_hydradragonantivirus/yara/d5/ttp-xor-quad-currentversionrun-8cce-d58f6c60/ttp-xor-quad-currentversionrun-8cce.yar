rule TTP_XOR_QUAD_CurrentVersionRun_8cce {
  strings:
    $key_8cce = { df a1 [2] fb af [2] d0 83 [2] fe a1 [2] ea ba [2] e5 a0 [2] fb bd [2] f9 bc [2] e2 ba [2] fe bd [2] e2 92 }

  condition:
    any of them
}