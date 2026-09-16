rule TTP_XOR_QUAD_CurrentVersionRun_39a1 {
  strings:
    $key_39a1 = { 6a ce [2] 4e c0 [2] 65 ec [2] 4b ce [2] 5f d5 [2] 50 cf [2] 4e d2 [2] 4c d3 [2] 57 d5 [2] 4b d2 [2] 57 fd }

  condition:
    any of them
}