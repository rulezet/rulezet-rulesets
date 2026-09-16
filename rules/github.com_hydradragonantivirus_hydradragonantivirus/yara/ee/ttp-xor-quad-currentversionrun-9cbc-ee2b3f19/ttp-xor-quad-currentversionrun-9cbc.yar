rule TTP_XOR_QUAD_CurrentVersionRun_9cbc {
  strings:
    $key_9cbc = { cf d3 [2] eb dd [2] c0 f1 [2] ee d3 [2] fa c8 [2] f5 d2 [2] eb cf [2] e9 ce [2] f2 c8 [2] ee cf [2] f2 e0 }

  condition:
    any of them
}