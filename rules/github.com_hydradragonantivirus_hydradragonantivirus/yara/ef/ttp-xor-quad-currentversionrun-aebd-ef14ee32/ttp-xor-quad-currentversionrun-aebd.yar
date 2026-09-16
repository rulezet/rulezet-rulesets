rule TTP_XOR_QUAD_CurrentVersionRun_aebd {
  strings:
    $key_aebd = { fd d2 [2] d9 dc [2] f2 f0 [2] dc d2 [2] c8 c9 [2] c7 d3 [2] d9 ce [2] db cf [2] c0 c9 [2] dc ce [2] c0 e1 }

  condition:
    any of them
}