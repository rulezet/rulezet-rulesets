rule TTP_XOR_QUAD_CurrentVersionRun_a2a0 {
  strings:
    $key_a2a0 = { f1 cf [2] d5 c1 [2] fe ed [2] d0 cf [2] c4 d4 [2] cb ce [2] d5 d3 [2] d7 d2 [2] cc d4 [2] d0 d3 [2] cc fc }

  condition:
    any of them
}