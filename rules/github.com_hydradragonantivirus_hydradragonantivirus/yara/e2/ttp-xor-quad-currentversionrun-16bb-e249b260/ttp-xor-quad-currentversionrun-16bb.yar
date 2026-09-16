rule TTP_XOR_QUAD_CurrentVersionRun_16bb {
  strings:
    $key_16bb = { 45 d4 [2] 61 da [2] 4a f6 [2] 64 d4 [2] 70 cf [2] 7f d5 [2] 61 c8 [2] 63 c9 [2] 78 cf [2] 64 c8 [2] 78 e7 }

  condition:
    any of them
}