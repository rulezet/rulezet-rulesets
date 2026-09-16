rule TTP_XOR_QUAD_CurrentVersionRun_64ae {
  strings:
    $key_64ae = { 37 c1 [2] 13 cf [2] 38 e3 [2] 16 c1 [2] 02 da [2] 0d c0 [2] 13 dd [2] 11 dc [2] 0a da [2] 16 dd [2] 0a f2 }

  condition:
    any of them
}