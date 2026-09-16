rule TTP_XOR_QUAD_CurrentVersionRun_9fbd {
  strings:
    $key_9fbd = { cc d2 [2] e8 dc [2] c3 f0 [2] ed d2 [2] f9 c9 [2] f6 d3 [2] e8 ce [2] ea cf [2] f1 c9 [2] ed ce [2] f1 e1 }

  condition:
    any of them
}