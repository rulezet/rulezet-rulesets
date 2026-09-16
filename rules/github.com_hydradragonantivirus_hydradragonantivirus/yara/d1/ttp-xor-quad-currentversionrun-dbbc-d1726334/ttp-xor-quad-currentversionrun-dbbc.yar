rule TTP_XOR_QUAD_CurrentVersionRun_dbbc {
  strings:
    $key_dbbc = { 88 d3 [2] ac dd [2] 87 f1 [2] a9 d3 [2] bd c8 [2] b2 d2 [2] ac cf [2] ae ce [2] b5 c8 [2] a9 cf [2] b5 e0 }

  condition:
    any of them
}