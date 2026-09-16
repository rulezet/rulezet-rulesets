rule TTP_XOR_QUAD_CurrentVersionRun_94bb {
  strings:
    $key_94bb = { c7 d4 [2] e3 da [2] c8 f6 [2] e6 d4 [2] f2 cf [2] fd d5 [2] e3 c8 [2] e1 c9 [2] fa cf [2] e6 c8 [2] fa e7 }

  condition:
    any of them
}