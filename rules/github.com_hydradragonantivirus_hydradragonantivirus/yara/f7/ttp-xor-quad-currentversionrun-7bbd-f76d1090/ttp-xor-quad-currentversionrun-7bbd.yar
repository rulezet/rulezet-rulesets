rule TTP_XOR_QUAD_CurrentVersionRun_7bbd {
  strings:
    $key_7bbd = { 28 d2 [2] 0c dc [2] 27 f0 [2] 09 d2 [2] 1d c9 [2] 12 d3 [2] 0c ce [2] 0e cf [2] 15 c9 [2] 09 ce [2] 15 e1 }

  condition:
    any of them
}