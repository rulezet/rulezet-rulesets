rule TTP_XOR_QUAD_CurrentVersionRun_68bd {
  strings:
    $key_68bd = { 3b d2 [2] 1f dc [2] 34 f0 [2] 1a d2 [2] 0e c9 [2] 01 d3 [2] 1f ce [2] 1d cf [2] 06 c9 [2] 1a ce [2] 06 e1 }

  condition:
    any of them
}