rule TTP_XOR_QUAD_CurrentVersionRun_9681 {
  strings:
    $key_9681 = { c5 ee [2] e1 e0 [2] ca cc [2] e4 ee [2] f0 f5 [2] ff ef [2] e1 f2 [2] e3 f3 [2] f8 f5 [2] e4 f2 [2] f8 dd }

  condition:
    any of them
}