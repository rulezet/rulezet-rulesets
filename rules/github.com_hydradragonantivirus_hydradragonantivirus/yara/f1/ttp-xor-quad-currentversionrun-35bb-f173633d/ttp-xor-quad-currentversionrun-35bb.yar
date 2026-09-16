rule TTP_XOR_QUAD_CurrentVersionRun_35bb {
  strings:
    $key_35bb = { 66 d4 [2] 42 da [2] 69 f6 [2] 47 d4 [2] 53 cf [2] 5c d5 [2] 42 c8 [2] 40 c9 [2] 5b cf [2] 47 c8 [2] 5b e7 }

  condition:
    any of them
}