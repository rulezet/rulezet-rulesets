rule TTP_XOR_QUAD_CurrentVersionRun_20a1 {
  strings:
    $key_20a1 = { 73 ce [2] 57 c0 [2] 7c ec [2] 52 ce [2] 46 d5 [2] 49 cf [2] 57 d2 [2] 55 d3 [2] 4e d5 [2] 52 d2 [2] 4e fd }

  condition:
    any of them
}