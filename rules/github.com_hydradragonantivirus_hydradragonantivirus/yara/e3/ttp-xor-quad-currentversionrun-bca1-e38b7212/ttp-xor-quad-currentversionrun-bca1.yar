rule TTP_XOR_QUAD_CurrentVersionRun_bca1 {
  strings:
    $key_bca1 = { ef ce [2] cb c0 [2] e0 ec [2] ce ce [2] da d5 [2] d5 cf [2] cb d2 [2] c9 d3 [2] d2 d5 [2] ce d2 [2] d2 fd }

  condition:
    any of them
}