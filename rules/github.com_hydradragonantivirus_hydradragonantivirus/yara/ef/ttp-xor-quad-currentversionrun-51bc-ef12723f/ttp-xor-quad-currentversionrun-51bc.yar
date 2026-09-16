rule TTP_XOR_QUAD_CurrentVersionRun_51bc {
  strings:
    $key_51bc = { 02 d3 [2] 26 dd [2] 0d f1 [2] 23 d3 [2] 37 c8 [2] 38 d2 [2] 26 cf [2] 24 ce [2] 3f c8 [2] 23 cf [2] 3f e0 }

  condition:
    any of them
}