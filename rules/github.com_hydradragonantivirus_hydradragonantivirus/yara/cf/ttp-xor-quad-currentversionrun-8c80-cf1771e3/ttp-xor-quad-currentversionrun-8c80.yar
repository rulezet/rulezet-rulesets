rule TTP_XOR_QUAD_CurrentVersionRun_8c80 {
  strings:
    $key_8c80 = { df ef [2] fb e1 [2] d0 cd [2] fe ef [2] ea f4 [2] e5 ee [2] fb f3 [2] f9 f2 [2] e2 f4 [2] fe f3 [2] e2 dc }

  condition:
    any of them
}