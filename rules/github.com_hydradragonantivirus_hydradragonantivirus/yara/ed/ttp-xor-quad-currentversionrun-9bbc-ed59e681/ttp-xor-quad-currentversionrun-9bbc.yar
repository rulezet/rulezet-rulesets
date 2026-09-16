rule TTP_XOR_QUAD_CurrentVersionRun_9bbc {
  strings:
    $key_9bbc = { c8 d3 [2] ec dd [2] c7 f1 [2] e9 d3 [2] fd c8 [2] f2 d2 [2] ec cf [2] ee ce [2] f5 c8 [2] e9 cf [2] f5 e0 }

  condition:
    any of them
}