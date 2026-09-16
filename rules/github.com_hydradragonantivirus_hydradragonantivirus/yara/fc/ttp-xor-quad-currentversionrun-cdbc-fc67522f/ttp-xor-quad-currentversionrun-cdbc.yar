rule TTP_XOR_QUAD_CurrentVersionRun_cdbc {
  strings:
    $key_cdbc = { 9e d3 [2] ba dd [2] 91 f1 [2] bf d3 [2] ab c8 [2] a4 d2 [2] ba cf [2] b8 ce [2] a3 c8 [2] bf cf [2] a3 e0 }

  condition:
    any of them
}