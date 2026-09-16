rule TTP_XOR_QUAD_CurrentVersionRun_93bb {
  strings:
    $key_93bb = { c0 d4 [2] e4 da [2] cf f6 [2] e1 d4 [2] f5 cf [2] fa d5 [2] e4 c8 [2] e6 c9 [2] fd cf [2] e1 c8 [2] fd e7 }

  condition:
    any of them
}