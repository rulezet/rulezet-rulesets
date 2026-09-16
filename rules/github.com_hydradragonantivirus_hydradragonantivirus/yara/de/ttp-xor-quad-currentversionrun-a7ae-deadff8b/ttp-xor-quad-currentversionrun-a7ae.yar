rule TTP_XOR_QUAD_CurrentVersionRun_a7ae {
  strings:
    $key_a7ae = { f4 c1 [2] d0 cf [2] fb e3 [2] d5 c1 [2] c1 da [2] ce c0 [2] d0 dd [2] d2 dc [2] c9 da [2] d5 dd [2] c9 f2 }

  condition:
    any of them
}