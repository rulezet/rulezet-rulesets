rule TTP_XOR_QUAD_CurrentVersionRun_00a1 {
  strings:
    $key_00a1 = { 53 ce [2] 77 c0 [2] 5c ec [2] 72 ce [2] 66 d5 [2] 69 cf [2] 77 d2 [2] 75 d3 [2] 6e d5 [2] 72 d2 [2] 6e fd }

  condition:
    any of them
}