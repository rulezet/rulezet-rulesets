rule TTP_XOR_QUAD_CurrentVersionRun_1ebd {
  strings:
    $key_1ebd = { 4d d2 [2] 69 dc [2] 42 f0 [2] 6c d2 [2] 78 c9 [2] 77 d3 [2] 69 ce [2] 6b cf [2] 70 c9 [2] 6c ce [2] 70 e1 }

  condition:
    any of them
}