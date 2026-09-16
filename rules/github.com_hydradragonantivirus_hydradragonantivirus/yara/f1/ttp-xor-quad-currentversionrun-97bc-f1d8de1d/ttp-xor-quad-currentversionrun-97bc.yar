rule TTP_XOR_QUAD_CurrentVersionRun_97bc {
  strings:
    $key_97bc = { c4 d3 [2] e0 dd [2] cb f1 [2] e5 d3 [2] f1 c8 [2] fe d2 [2] e0 cf [2] e2 ce [2] f9 c8 [2] e5 cf [2] f9 e0 }

  condition:
    any of them
}