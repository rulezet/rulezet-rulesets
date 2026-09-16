rule TTP_XOR_QUAD_CurrentVersionRun_26a1 {
  strings:
    $key_26a1 = { 75 ce [2] 51 c0 [2] 7a ec [2] 54 ce [2] 40 d5 [2] 4f cf [2] 51 d2 [2] 53 d3 [2] 48 d5 [2] 54 d2 [2] 48 fd }

  condition:
    any of them
}