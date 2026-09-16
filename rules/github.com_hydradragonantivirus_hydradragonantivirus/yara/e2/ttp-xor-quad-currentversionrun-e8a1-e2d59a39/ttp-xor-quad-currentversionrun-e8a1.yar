rule TTP_XOR_QUAD_CurrentVersionRun_e8a1 {
  strings:
    $key_e8a1 = { bb ce [2] 9f c0 [2] b4 ec [2] 9a ce [2] 8e d5 [2] 81 cf [2] 9f d2 [2] 9d d3 [2] 86 d5 [2] 9a d2 [2] 86 fd }

  condition:
    any of them
}