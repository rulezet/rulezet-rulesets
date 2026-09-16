rule TTP_XOR_QUAD_CurrentVersionRun_97bd {
  strings:
    $key_97bd = { c4 d2 [2] e0 dc [2] cb f0 [2] e5 d2 [2] f1 c9 [2] fe d3 [2] e0 ce [2] e2 cf [2] f9 c9 [2] e5 ce [2] f9 e1 }

  condition:
    any of them
}