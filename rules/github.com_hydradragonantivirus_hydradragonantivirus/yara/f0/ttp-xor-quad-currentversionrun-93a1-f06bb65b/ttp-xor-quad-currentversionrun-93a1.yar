rule TTP_XOR_QUAD_CurrentVersionRun_93a1 {
  strings:
    $key_93a1 = { c0 ce [2] e4 c0 [2] cf ec [2] e1 ce [2] f5 d5 [2] fa cf [2] e4 d2 [2] e6 d3 [2] fd d5 [2] e1 d2 [2] fd fd }

  condition:
    any of them
}