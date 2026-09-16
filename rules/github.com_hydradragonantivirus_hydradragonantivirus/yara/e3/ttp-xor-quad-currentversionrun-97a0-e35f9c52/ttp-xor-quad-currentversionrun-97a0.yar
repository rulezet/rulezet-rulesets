rule TTP_XOR_QUAD_CurrentVersionRun_97a0 {
  strings:
    $key_97a0 = { c4 cf [2] e0 c1 [2] cb ed [2] e5 cf [2] f1 d4 [2] fe ce [2] e0 d3 [2] e2 d2 [2] f9 d4 [2] e5 d3 [2] f9 fc }

  condition:
    any of them
}