rule TTP_XOR_QUAD_CurrentVersionRun_b4bb {
  strings:
    $key_b4bb = { e7 d4 [2] c3 da [2] e8 f6 [2] c6 d4 [2] d2 cf [2] dd d5 [2] c3 c8 [2] c1 c9 [2] da cf [2] c6 c8 [2] da e7 }

  condition:
    any of them
}