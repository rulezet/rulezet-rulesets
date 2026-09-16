rule TTP_XOR_QUAD_CurrentVersionRun_9da1 {
  strings:
    $key_9da1 = { ce ce [2] ea c0 [2] c1 ec [2] ef ce [2] fb d5 [2] f4 cf [2] ea d2 [2] e8 d3 [2] f3 d5 [2] ef d2 [2] f3 fd }

  condition:
    any of them
}