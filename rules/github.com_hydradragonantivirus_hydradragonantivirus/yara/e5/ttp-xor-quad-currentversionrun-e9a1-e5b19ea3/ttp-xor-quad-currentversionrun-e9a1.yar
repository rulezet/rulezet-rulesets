rule TTP_XOR_QUAD_CurrentVersionRun_e9a1 {
  strings:
    $key_e9a1 = { ba ce [2] 9e c0 [2] b5 ec [2] 9b ce [2] 8f d5 [2] 80 cf [2] 9e d2 [2] 9c d3 [2] 87 d5 [2] 9b d2 [2] 87 fd }

  condition:
    any of them
}