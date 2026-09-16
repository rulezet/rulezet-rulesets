rule TTP_XOR_QUAD_CurrentVersionRun_12bb {
  strings:
    $key_12bb = { 41 d4 [2] 65 da [2] 4e f6 [2] 60 d4 [2] 74 cf [2] 7b d5 [2] 65 c8 [2] 67 c9 [2] 7c cf [2] 60 c8 [2] 7c e7 }

  condition:
    any of them
}