rule TTP_XOR_QUAD_CurrentVersionRun_b1bb {
  strings:
    $key_b1bb = { e2 d4 [2] c6 da [2] ed f6 [2] c3 d4 [2] d7 cf [2] d8 d5 [2] c6 c8 [2] c4 c9 [2] df cf [2] c3 c8 [2] df e7 }

  condition:
    any of them
}