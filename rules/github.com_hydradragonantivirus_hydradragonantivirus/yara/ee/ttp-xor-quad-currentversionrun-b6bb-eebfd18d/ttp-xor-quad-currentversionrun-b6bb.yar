rule TTP_XOR_QUAD_CurrentVersionRun_b6bb {
  strings:
    $key_b6bb = { e5 d4 [2] c1 da [2] ea f6 [2] c4 d4 [2] d0 cf [2] df d5 [2] c1 c8 [2] c3 c9 [2] d8 cf [2] c4 c8 [2] d8 e7 }

  condition:
    any of them
}