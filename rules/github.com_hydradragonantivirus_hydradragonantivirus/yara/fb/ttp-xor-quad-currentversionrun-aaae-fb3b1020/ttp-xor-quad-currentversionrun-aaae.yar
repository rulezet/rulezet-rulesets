rule TTP_XOR_QUAD_CurrentVersionRun_aaae {
  strings:
    $key_aaae = { f9 c1 [2] dd cf [2] f6 e3 [2] d8 c1 [2] cc da [2] c3 c0 [2] dd dd [2] df dc [2] c4 da [2] d8 dd [2] c4 f2 }

  condition:
    any of them
}