rule TTP_XOR_QUAD_CurrentVersionRun_d4bc {
  strings:
    $key_d4bc = { 87 d3 [2] a3 dd [2] 88 f1 [2] a6 d3 [2] b2 c8 [2] bd d2 [2] a3 cf [2] a1 ce [2] ba c8 [2] a6 cf [2] ba e0 }

  condition:
    any of them
}