rule TTP_XOR_QUAD_CurrentVersionRun_04ae {
  strings:
    $key_04ae = { 57 c1 [2] 73 cf [2] 58 e3 [2] 76 c1 [2] 62 da [2] 6d c0 [2] 73 dd [2] 71 dc [2] 6a da [2] 76 dd [2] 6a f2 }

  condition:
    any of them
}