rule TTP_XOR_QUAD_CurrentVersionRun_0bbd {
  strings:
    $key_0bbd = { 58 d2 [2] 7c dc [2] 57 f0 [2] 79 d2 [2] 6d c9 [2] 62 d3 [2] 7c ce [2] 7e cf [2] 65 c9 [2] 79 ce [2] 65 e1 }

  condition:
    any of them
}