rule TTP_XOR_QUAD_CurrentVersionRun_54bb {
  strings:
    $key_54bb = { 07 d4 [2] 23 da [2] 08 f6 [2] 26 d4 [2] 32 cf [2] 3d d5 [2] 23 c8 [2] 21 c9 [2] 3a cf [2] 26 c8 [2] 3a e7 }

  condition:
    any of them
}