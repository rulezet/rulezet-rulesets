rule TTP_XOR_QUAD_CurrentVersionRun_76bb {
  strings:
    $key_76bb = { 25 d4 [2] 01 da [2] 2a f6 [2] 04 d4 [2] 10 cf [2] 1f d5 [2] 01 c8 [2] 03 c9 [2] 18 cf [2] 04 c8 [2] 18 e7 }

  condition:
    any of them
}