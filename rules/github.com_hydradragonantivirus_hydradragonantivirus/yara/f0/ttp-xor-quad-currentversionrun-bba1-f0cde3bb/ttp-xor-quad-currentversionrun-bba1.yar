rule TTP_XOR_QUAD_CurrentVersionRun_bba1 {
  strings:
    $key_bba1 = { e8 ce [2] cc c0 [2] e7 ec [2] c9 ce [2] dd d5 [2] d2 cf [2] cc d2 [2] ce d3 [2] d5 d5 [2] c9 d2 [2] d5 fd }

  condition:
    any of them
}