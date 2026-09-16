rule TTP_XOR_QUAD_CurrentVersionRun_8ea0 {
  strings:
    $key_8ea0 = { dd cf [2] f9 c1 [2] d2 ed [2] fc cf [2] e8 d4 [2] e7 ce [2] f9 d3 [2] fb d2 [2] e0 d4 [2] fc d3 [2] e0 fc }

  condition:
    any of them
}