rule TTP_XOR_QUAD_CurrentVersionRun_51ae {
  strings:
    $key_51ae = { 02 c1 [2] 26 cf [2] 0d e3 [2] 23 c1 [2] 37 da [2] 38 c0 [2] 26 dd [2] 24 dc [2] 3f da [2] 23 dd [2] 3f f2 }

  condition:
    any of them
}