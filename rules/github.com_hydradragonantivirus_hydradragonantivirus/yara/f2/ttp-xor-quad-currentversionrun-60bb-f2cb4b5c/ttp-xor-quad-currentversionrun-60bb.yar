rule TTP_XOR_QUAD_CurrentVersionRun_60bb {
  strings:
    $key_60bb = { 33 d4 [2] 17 da [2] 3c f6 [2] 12 d4 [2] 06 cf [2] 09 d5 [2] 17 c8 [2] 15 c9 [2] 0e cf [2] 12 c8 [2] 0e e7 }

  condition:
    any of them
}