rule TTP_XOR_QUAD_CurrentVersionRun_69bd {
  strings:
    $key_69bd = { 3a d2 [2] 1e dc [2] 35 f0 [2] 1b d2 [2] 0f c9 [2] 00 d3 [2] 1e ce [2] 1c cf [2] 07 c9 [2] 1b ce [2] 07 e1 }

  condition:
    any of them
}