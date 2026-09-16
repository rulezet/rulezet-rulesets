rule TTP_XOR_QUAD_CurrentVersionRun_94bd {
  strings:
    $key_94bd = { c7 d2 [2] e3 dc [2] c8 f0 [2] e6 d2 [2] f2 c9 [2] fd d3 [2] e3 ce [2] e1 cf [2] fa c9 [2] e6 ce [2] fa e1 }

  condition:
    any of them
}