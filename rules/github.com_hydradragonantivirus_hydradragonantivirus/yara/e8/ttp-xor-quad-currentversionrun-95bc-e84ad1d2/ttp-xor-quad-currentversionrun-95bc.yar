rule TTP_XOR_QUAD_CurrentVersionRun_95bc {
  strings:
    $key_95bc = { c6 d3 [2] e2 dd [2] c9 f1 [2] e7 d3 [2] f3 c8 [2] fc d2 [2] e2 cf [2] e0 ce [2] fb c8 [2] e7 cf [2] fb e0 }

  condition:
    any of them
}