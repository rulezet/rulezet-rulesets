rule TTP_XOR_QUAD_CurrentVersionRun_66bb {
  strings:
    $key_66bb = { 35 d4 [2] 11 da [2] 3a f6 [2] 14 d4 [2] 00 cf [2] 0f d5 [2] 11 c8 [2] 13 c9 [2] 08 cf [2] 14 c8 [2] 08 e7 }

  condition:
    any of them
}