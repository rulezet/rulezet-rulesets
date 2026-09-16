rule TTP_XOR_QUAD_CurrentVersionRun_fda1 {
  strings:
    $key_fda1 = { ae ce [2] 8a c0 [2] a1 ec [2] 8f ce [2] 9b d5 [2] 94 cf [2] 8a d2 [2] 88 d3 [2] 93 d5 [2] 8f d2 [2] 93 fd }

  condition:
    any of them
}