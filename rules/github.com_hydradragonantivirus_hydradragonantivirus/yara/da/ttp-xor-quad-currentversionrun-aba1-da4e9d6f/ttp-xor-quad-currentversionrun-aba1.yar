rule TTP_XOR_QUAD_CurrentVersionRun_aba1 {
  strings:
    $key_aba1 = { f8 ce [2] dc c0 [2] f7 ec [2] d9 ce [2] cd d5 [2] c2 cf [2] dc d2 [2] de d3 [2] c5 d5 [2] d9 d2 [2] c5 fd }

  condition:
    any of them
}