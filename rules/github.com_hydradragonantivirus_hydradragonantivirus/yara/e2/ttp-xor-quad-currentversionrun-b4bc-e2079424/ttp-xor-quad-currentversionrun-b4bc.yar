rule TTP_XOR_QUAD_CurrentVersionRun_b4bc {
  strings:
    $key_b4bc = { e7 d3 [2] c3 dd [2] e8 f1 [2] c6 d3 [2] d2 c8 [2] dd d2 [2] c3 cf [2] c1 ce [2] da c8 [2] c6 cf [2] da e0 }

  condition:
    any of them
}