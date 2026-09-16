rule TTP_XOR_QUAD_CurrentVersionRun_abbc {
  strings:
    $key_abbc = { f8 d3 [2] dc dd [2] f7 f1 [2] d9 d3 [2] cd c8 [2] c2 d2 [2] dc cf [2] de ce [2] c5 c8 [2] d9 cf [2] c5 e0 }

  condition:
    any of them
}