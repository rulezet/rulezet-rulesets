rule TTP_XOR_QUAD_CurrentVersionRun_cdae {
  strings:
    $key_cdae = { 9e c1 [2] ba cf [2] 91 e3 [2] bf c1 [2] ab da [2] a4 c0 [2] ba dd [2] b8 dc [2] a3 da [2] bf dd [2] a3 f2 }

  condition:
    any of them
}