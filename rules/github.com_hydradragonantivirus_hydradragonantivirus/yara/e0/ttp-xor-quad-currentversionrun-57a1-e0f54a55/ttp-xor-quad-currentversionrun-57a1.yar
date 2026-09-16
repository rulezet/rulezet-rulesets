rule TTP_XOR_QUAD_CurrentVersionRun_57a1 {
  strings:
    $key_57a1 = { 04 ce [2] 20 c0 [2] 0b ec [2] 25 ce [2] 31 d5 [2] 3e cf [2] 20 d2 [2] 22 d3 [2] 39 d5 [2] 25 d2 [2] 39 fd }

  condition:
    any of them
}