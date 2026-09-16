rule TTP_XOR_QUAD_CurrentVersionRun_20bb {
  strings:
    $key_20bb = { 73 d4 [2] 57 da [2] 7c f6 [2] 52 d4 [2] 46 cf [2] 49 d5 [2] 57 c8 [2] 55 c9 [2] 4e cf [2] 52 c8 [2] 4e e7 }

  condition:
    any of them
}