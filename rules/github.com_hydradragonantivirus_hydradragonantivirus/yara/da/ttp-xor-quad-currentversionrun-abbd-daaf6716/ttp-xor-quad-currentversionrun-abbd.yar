rule TTP_XOR_QUAD_CurrentVersionRun_abbd {
  strings:
    $key_abbd = { f8 d2 [2] dc dc [2] f7 f0 [2] d9 d2 [2] cd c9 [2] c2 d3 [2] dc ce [2] de cf [2] c5 c9 [2] d9 ce [2] c5 e1 }

  condition:
    any of them
}