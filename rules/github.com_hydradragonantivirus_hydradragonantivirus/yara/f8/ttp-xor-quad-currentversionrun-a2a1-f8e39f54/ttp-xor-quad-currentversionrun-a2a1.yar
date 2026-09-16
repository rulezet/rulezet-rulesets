rule TTP_XOR_QUAD_CurrentVersionRun_a2a1 {
  strings:
    $key_a2a1 = { f1 ce [2] d5 c0 [2] fe ec [2] d0 ce [2] c4 d5 [2] cb cf [2] d5 d2 [2] d7 d3 [2] cc d5 [2] d0 d2 [2] cc fd }

  condition:
    any of them
}