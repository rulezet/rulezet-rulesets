rule TTP_XOR_QUAD_CurrentVersionRun_efbd {
  strings:
    $key_efbd = { bc d2 [2] 98 dc [2] b3 f0 [2] 9d d2 [2] 89 c9 [2] 86 d3 [2] 98 ce [2] 9a cf [2] 81 c9 [2] 9d ce [2] 81 e1 }

  condition:
    any of them
}