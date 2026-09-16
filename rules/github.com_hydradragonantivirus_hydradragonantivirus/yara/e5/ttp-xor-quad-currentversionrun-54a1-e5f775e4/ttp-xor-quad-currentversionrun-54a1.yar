rule TTP_XOR_QUAD_CurrentVersionRun_54a1 {
  strings:
    $key_54a1 = { 07 ce [2] 23 c0 [2] 08 ec [2] 26 ce [2] 32 d5 [2] 3d cf [2] 23 d2 [2] 21 d3 [2] 3a d5 [2] 26 d2 [2] 3a fd }

  condition:
    any of them
}