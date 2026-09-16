rule TTP_XOR_QUAD_CurrentVersionRun_f4a1 {
  strings:
    $key_f4a1 = { a7 ce [2] 83 c0 [2] a8 ec [2] 86 ce [2] 92 d5 [2] 9d cf [2] 83 d2 [2] 81 d3 [2] 9a d5 [2] 86 d2 [2] 9a fd }

  condition:
    any of them
}