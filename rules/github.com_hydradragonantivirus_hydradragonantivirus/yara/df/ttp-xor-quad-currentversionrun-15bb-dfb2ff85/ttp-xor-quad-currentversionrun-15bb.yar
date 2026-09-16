rule TTP_XOR_QUAD_CurrentVersionRun_15bb {
  strings:
    $key_15bb = { 46 d4 [2] 62 da [2] 49 f6 [2] 67 d4 [2] 73 cf [2] 7c d5 [2] 62 c8 [2] 60 c9 [2] 7b cf [2] 67 c8 [2] 7b e7 }

  condition:
    any of them
}