rule TTP_XOR_QUAD_CurrentVersionRun_bea1 {
  strings:
    $key_bea1 = { ed ce [2] c9 c0 [2] e2 ec [2] cc ce [2] d8 d5 [2] d7 cf [2] c9 d2 [2] cb d3 [2] d0 d5 [2] cc d2 [2] d0 fd }

  condition:
    any of them
}