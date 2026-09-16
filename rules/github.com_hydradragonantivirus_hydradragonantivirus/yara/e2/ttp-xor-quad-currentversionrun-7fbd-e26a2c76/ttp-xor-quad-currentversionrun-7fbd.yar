rule TTP_XOR_QUAD_CurrentVersionRun_7fbd {
  strings:
    $key_7fbd = { 2c d2 [2] 08 dc [2] 23 f0 [2] 0d d2 [2] 19 c9 [2] 16 d3 [2] 08 ce [2] 0a cf [2] 11 c9 [2] 0d ce [2] 11 e1 }

  condition:
    any of them
}