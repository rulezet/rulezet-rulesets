rule TTP_XOR_QUAD_CurrentVersionRun_b5bb {
  strings:
    $key_b5bb = { e6 d4 [2] c2 da [2] e9 f6 [2] c7 d4 [2] d3 cf [2] dc d5 [2] c2 c8 [2] c0 c9 [2] db cf [2] c7 c8 [2] db e7 }

  condition:
    any of them
}