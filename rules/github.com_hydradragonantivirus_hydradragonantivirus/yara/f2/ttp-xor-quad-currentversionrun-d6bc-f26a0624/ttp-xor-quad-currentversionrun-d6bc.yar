rule TTP_XOR_QUAD_CurrentVersionRun_d6bc {
  strings:
    $key_d6bc = { 85 d3 [2] a1 dd [2] 8a f1 [2] a4 d3 [2] b0 c8 [2] bf d2 [2] a1 cf [2] a3 ce [2] b8 c8 [2] a4 cf [2] b8 e0 }

  condition:
    any of them
}