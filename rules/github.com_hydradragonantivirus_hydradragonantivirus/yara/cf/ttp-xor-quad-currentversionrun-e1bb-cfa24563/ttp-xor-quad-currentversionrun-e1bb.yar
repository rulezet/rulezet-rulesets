rule TTP_XOR_QUAD_CurrentVersionRun_e1bb {
  strings:
    $key_e1bb = { b2 d4 [2] 96 da [2] bd f6 [2] 93 d4 [2] 87 cf [2] 88 d5 [2] 96 c8 [2] 94 c9 [2] 8f cf [2] 93 c8 [2] 8f e7 }

  condition:
    any of them
}