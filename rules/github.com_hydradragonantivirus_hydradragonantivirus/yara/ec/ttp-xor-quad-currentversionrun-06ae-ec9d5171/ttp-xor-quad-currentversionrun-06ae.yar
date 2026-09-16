rule TTP_XOR_QUAD_CurrentVersionRun_06ae {
  strings:
    $key_06ae = { 55 c1 [2] 71 cf [2] 5a e3 [2] 74 c1 [2] 60 da [2] 6f c0 [2] 71 dd [2] 73 dc [2] 68 da [2] 74 dd [2] 68 f2 }

  condition:
    any of them
}