rule TTP_XOR_QUAD_CurrentVersionRun_bcae {
  strings:
    $key_bcae = { ef c1 [2] cb cf [2] e0 e3 [2] ce c1 [2] da da [2] d5 c0 [2] cb dd [2] c9 dc [2] d2 da [2] ce dd [2] d2 f2 }

  condition:
    any of them
}