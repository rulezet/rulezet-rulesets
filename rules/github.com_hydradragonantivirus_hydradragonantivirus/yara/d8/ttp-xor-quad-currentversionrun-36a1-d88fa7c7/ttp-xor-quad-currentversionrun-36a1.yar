rule TTP_XOR_QUAD_CurrentVersionRun_36a1 {
  strings:
    $key_36a1 = { 65 ce [2] 41 c0 [2] 6a ec [2] 44 ce [2] 50 d5 [2] 5f cf [2] 41 d2 [2] 43 d3 [2] 58 d5 [2] 44 d2 [2] 58 fd }

  condition:
    any of them
}