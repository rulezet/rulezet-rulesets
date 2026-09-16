rule TTP_XOR_QUAD_CurrentVersionRun_b1bc {
  strings:
    $key_b1bc = { e2 d3 [2] c6 dd [2] ed f1 [2] c3 d3 [2] d7 c8 [2] d8 d2 [2] c6 cf [2] c4 ce [2] df c8 [2] c3 cf [2] df e0 }

  condition:
    any of them
}