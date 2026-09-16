rule TTP_XOR_QUAD_CurrentVersionRun_8ea1 {
  strings:
    $key_8ea1 = { dd ce [2] f9 c0 [2] d2 ec [2] fc ce [2] e8 d5 [2] e7 cf [2] f9 d2 [2] fb d3 [2] e0 d5 [2] fc d2 [2] e0 fd }

  condition:
    any of them
}