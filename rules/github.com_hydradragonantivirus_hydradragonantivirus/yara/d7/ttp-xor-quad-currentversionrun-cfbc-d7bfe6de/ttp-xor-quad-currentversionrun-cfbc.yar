rule TTP_XOR_QUAD_CurrentVersionRun_cfbc {
  strings:
    $key_cfbc = { 9c d3 [2] b8 dd [2] 93 f1 [2] bd d3 [2] a9 c8 [2] a6 d2 [2] b8 cf [2] ba ce [2] a1 c8 [2] bd cf [2] a1 e0 }

  condition:
    any of them
}