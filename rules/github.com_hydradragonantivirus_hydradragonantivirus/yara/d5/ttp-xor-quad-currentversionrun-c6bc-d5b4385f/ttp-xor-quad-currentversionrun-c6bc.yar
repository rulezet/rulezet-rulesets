rule TTP_XOR_QUAD_CurrentVersionRun_c6bc {
  strings:
    $key_c6bc = { 95 d3 [2] b1 dd [2] 9a f1 [2] b4 d3 [2] a0 c8 [2] af d2 [2] b1 cf [2] b3 ce [2] a8 c8 [2] b4 cf [2] a8 e0 }

  condition:
    any of them
}