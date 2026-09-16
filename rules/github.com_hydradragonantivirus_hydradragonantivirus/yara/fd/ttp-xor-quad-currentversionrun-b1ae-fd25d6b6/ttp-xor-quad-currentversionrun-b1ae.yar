rule TTP_XOR_QUAD_CurrentVersionRun_b1ae {
  strings:
    $key_b1ae = { e2 c1 [2] c6 cf [2] ed e3 [2] c3 c1 [2] d7 da [2] d8 c0 [2] c6 dd [2] c4 dc [2] df da [2] c3 dd [2] df f2 }

  condition:
    any of them
}