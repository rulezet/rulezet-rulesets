rule TTP_XOR_QUAD_CurrentVersionRun_e1bd {
  strings:
    $key_e1bd = { b2 d2 [2] 96 dc [2] bd f0 [2] 93 d2 [2] 87 c9 [2] 88 d3 [2] 96 ce [2] 94 cf [2] 8f c9 [2] 93 ce [2] 8f e1 }

  condition:
    any of them
}