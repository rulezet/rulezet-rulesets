rule TTP_XOR_QUAD_CurrentVersionRun_d1bc {
  strings:
    $key_d1bc = { 82 d3 [2] a6 dd [2] 8d f1 [2] a3 d3 [2] b7 c8 [2] b8 d2 [2] a6 cf [2] a4 ce [2] bf c8 [2] a3 cf [2] bf e0 }

  condition:
    any of them
}