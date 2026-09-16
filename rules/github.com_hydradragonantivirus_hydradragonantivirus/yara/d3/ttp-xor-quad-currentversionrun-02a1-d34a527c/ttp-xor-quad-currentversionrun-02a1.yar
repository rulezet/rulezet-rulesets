rule TTP_XOR_QUAD_CurrentVersionRun_02a1 {
  strings:
    $key_02a1 = { 51 ce [2] 75 c0 [2] 5e ec [2] 70 ce [2] 64 d5 [2] 6b cf [2] 75 d2 [2] 77 d3 [2] 6c d5 [2] 70 d2 [2] 6c fd }

  condition:
    any of them
}