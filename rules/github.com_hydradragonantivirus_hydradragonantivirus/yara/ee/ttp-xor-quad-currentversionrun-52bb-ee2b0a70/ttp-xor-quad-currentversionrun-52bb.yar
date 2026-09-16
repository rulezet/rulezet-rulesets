rule TTP_XOR_QUAD_CurrentVersionRun_52bb {
  strings:
    $key_52bb = { 01 d4 [2] 25 da [2] 0e f6 [2] 20 d4 [2] 34 cf [2] 3b d5 [2] 25 c8 [2] 27 c9 [2] 3c cf [2] 20 c8 [2] 3c e7 }

  condition:
    any of them
}