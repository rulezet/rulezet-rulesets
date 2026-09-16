rule TTP_XOR_QUAD_CurrentVersionRun_11a1 {
  strings:
    $key_11a1 = { 42 ce [2] 66 c0 [2] 4d ec [2] 63 ce [2] 77 d5 [2] 78 cf [2] 66 d2 [2] 64 d3 [2] 7f d5 [2] 63 d2 [2] 7f fd }

  condition:
    any of them
}