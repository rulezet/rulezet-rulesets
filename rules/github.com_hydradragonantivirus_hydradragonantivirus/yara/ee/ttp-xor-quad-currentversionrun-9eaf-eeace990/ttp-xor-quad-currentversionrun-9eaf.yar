rule TTP_XOR_QUAD_CurrentVersionRun_9eaf {
  strings:
    $key_9eaf = { cd c0 [2] e9 ce [2] c2 e2 [2] ec c0 [2] f8 db [2] f7 c1 [2] e9 dc [2] eb dd [2] f0 db [2] ec dc [2] f0 f3 }

  condition:
    any of them
}