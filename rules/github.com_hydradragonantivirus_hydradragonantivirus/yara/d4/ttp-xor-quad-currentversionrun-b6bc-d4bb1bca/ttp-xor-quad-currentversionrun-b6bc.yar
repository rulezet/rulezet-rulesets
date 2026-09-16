rule TTP_XOR_QUAD_CurrentVersionRun_b6bc {
  strings:
    $key_b6bc = { e5 d3 [2] c1 dd [2] ea f1 [2] c4 d3 [2] d0 c8 [2] df d2 [2] c1 cf [2] c3 ce [2] d8 c8 [2] c4 cf [2] d8 e0 }

  condition:
    any of them
}