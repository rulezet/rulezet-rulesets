rule TTP_XOR_QUAD_CurrentVersionRun_62bb {
  strings:
    $key_62bb = { 31 d4 [2] 15 da [2] 3e f6 [2] 10 d4 [2] 04 cf [2] 0b d5 [2] 15 c8 [2] 17 c9 [2] 0c cf [2] 10 c8 [2] 0c e7 }

  condition:
    any of them
}