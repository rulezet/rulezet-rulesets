rule TTP_XOR_QUAD_CurrentVersionRun_02bb {
  strings:
    $key_02bb = { 51 d4 [2] 75 da [2] 5e f6 [2] 70 d4 [2] 64 cf [2] 6b d5 [2] 75 c8 [2] 77 c9 [2] 6c cf [2] 70 c8 [2] 6c e7 }

  condition:
    any of them
}