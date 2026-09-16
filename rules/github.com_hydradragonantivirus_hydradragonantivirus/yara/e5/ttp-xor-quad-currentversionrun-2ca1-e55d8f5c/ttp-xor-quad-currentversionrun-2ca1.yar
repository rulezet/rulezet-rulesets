rule TTP_XOR_QUAD_CurrentVersionRun_2ca1 {
  strings:
    $key_2ca1 = { 7f ce [2] 5b c0 [2] 70 ec [2] 5e ce [2] 4a d5 [2] 45 cf [2] 5b d2 [2] 59 d3 [2] 42 d5 [2] 5e d2 [2] 42 fd }

  condition:
    any of them
}