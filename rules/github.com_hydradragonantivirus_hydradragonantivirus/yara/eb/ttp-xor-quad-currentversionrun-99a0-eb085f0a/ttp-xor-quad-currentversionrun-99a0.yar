rule TTP_XOR_QUAD_CurrentVersionRun_99a0 {
  strings:
    $key_99a0 = { ca cf [2] ee c1 [2] c5 ed [2] eb cf [2] ff d4 [2] f0 ce [2] ee d3 [2] ec d2 [2] f7 d4 [2] eb d3 [2] f7 fc }

  condition:
    any of them
}