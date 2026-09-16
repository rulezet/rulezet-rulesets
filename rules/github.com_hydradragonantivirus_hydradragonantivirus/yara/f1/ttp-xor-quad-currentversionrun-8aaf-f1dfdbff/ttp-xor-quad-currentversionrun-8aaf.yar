rule TTP_XOR_QUAD_CurrentVersionRun_8aaf {
  strings:
    $key_8aaf = { d9 c0 [2] fd ce [2] d6 e2 [2] f8 c0 [2] ec db [2] e3 c1 [2] fd dc [2] ff dd [2] e4 db [2] f8 dc [2] e4 f3 }

  condition:
    any of them
}