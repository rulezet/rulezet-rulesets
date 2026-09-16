rule TTP_XOR_QUAD_CurrentVersionRun_22bb {
  strings:
    $key_22bb = { 71 d4 [2] 55 da [2] 7e f6 [2] 50 d4 [2] 44 cf [2] 4b d5 [2] 55 c8 [2] 57 c9 [2] 4c cf [2] 50 c8 [2] 4c e7 }

  condition:
    any of them
}