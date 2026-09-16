rule TTP_XOR_QUAD_CurrentVersionRun_b3ae {
  strings:
    $key_b3ae = { e0 c1 [2] c4 cf [2] ef e3 [2] c1 c1 [2] d5 da [2] da c0 [2] c4 dd [2] c6 dc [2] dd da [2] c1 dd [2] dd f2 }

  condition:
    any of them
}