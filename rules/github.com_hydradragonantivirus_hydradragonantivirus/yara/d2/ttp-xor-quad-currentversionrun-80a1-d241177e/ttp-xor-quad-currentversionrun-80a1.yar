rule TTP_XOR_QUAD_CurrentVersionRun_80a1 {
  strings:
    $key_80a1 = { d3 ce [2] f7 c0 [2] dc ec [2] f2 ce [2] e6 d5 [2] e9 cf [2] f7 d2 [2] f5 d3 [2] ee d5 [2] f2 d2 [2] ee fd }

  condition:
    any of them
}