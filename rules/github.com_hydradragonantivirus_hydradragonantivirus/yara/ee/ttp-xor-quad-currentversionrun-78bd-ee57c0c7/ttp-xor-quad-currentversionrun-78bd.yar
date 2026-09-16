rule TTP_XOR_QUAD_CurrentVersionRun_78bd {
  strings:
    $key_78bd = { 2b d2 [2] 0f dc [2] 24 f0 [2] 0a d2 [2] 1e c9 [2] 11 d3 [2] 0f ce [2] 0d cf [2] 16 c9 [2] 0a ce [2] 16 e1 }

  condition:
    any of them
}