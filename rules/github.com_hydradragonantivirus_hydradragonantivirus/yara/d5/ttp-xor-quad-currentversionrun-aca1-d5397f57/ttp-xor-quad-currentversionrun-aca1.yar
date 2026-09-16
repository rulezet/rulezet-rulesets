rule TTP_XOR_QUAD_CurrentVersionRun_aca1 {
  strings:
    $key_aca1 = { ff ce [2] db c0 [2] f0 ec [2] de ce [2] ca d5 [2] c5 cf [2] db d2 [2] d9 d3 [2] c2 d5 [2] de d2 [2] c2 fd }

  condition:
    any of them
}