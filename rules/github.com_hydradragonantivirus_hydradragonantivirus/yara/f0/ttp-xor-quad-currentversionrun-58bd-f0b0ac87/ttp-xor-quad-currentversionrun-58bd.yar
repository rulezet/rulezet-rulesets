rule TTP_XOR_QUAD_CurrentVersionRun_58bd {
  strings:
    $key_58bd = { 0b d2 [2] 2f dc [2] 04 f0 [2] 2a d2 [2] 3e c9 [2] 31 d3 [2] 2f ce [2] 2d cf [2] 36 c9 [2] 2a ce [2] 36 e1 }

  condition:
    any of them
}