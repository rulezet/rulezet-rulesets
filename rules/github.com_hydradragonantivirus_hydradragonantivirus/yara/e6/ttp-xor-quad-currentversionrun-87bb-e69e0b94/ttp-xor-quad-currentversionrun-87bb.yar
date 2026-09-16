rule TTP_XOR_QUAD_CurrentVersionRun_87bb {
  strings:
    $key_87bb = { d4 d4 [2] f0 da [2] db f6 [2] f5 d4 [2] e1 cf [2] ee d5 [2] f0 c8 [2] f2 c9 [2] e9 cf [2] f5 c8 [2] e9 e7 }

  condition:
    any of them
}