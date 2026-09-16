rule TTP_XOR_QUAD_CurrentVersionRun_48bd {
  strings:
    $key_48bd = { 1b d2 [2] 3f dc [2] 14 f0 [2] 3a d2 [2] 2e c9 [2] 21 d3 [2] 3f ce [2] 3d cf [2] 26 c9 [2] 3a ce [2] 26 e1 }

  condition:
    any of them
}