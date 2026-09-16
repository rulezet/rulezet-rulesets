rule TTP_XOR_QUAD_CurrentVersionRun_9ca0 {
  strings:
    $key_9ca0 = { cf cf [2] eb c1 [2] c0 ed [2] ee cf [2] fa d4 [2] f5 ce [2] eb d3 [2] e9 d2 [2] f2 d4 [2] ee d3 [2] f2 fc }

  condition:
    any of them
}