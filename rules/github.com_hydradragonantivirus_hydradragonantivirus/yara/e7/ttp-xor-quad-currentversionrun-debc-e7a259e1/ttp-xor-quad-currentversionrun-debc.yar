rule TTP_XOR_QUAD_CurrentVersionRun_debc {
  strings:
    $key_debc = { 8d d3 [2] a9 dd [2] 82 f1 [2] ac d3 [2] b8 c8 [2] b7 d2 [2] a9 cf [2] ab ce [2] b0 c8 [2] ac cf [2] b0 e0 }

  condition:
    any of them
}