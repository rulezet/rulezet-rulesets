rule TTP_XOR_QUAD_CurrentVersionRun_9ea0 {
  strings:
    $key_9ea0 = { cd cf [2] e9 c1 [2] c2 ed [2] ec cf [2] f8 d4 [2] f7 ce [2] e9 d3 [2] eb d2 [2] f0 d4 [2] ec d3 [2] f0 fc }

  condition:
    any of them
}