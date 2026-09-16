rule TTP_XOR_QUAD_CurrentVersionRun_9ea8 {
  strings:
    $key_9ea8 = { cd c7 [2] e9 c9 [2] c2 e5 [2] ec c7 [2] f8 dc [2] f7 c6 [2] e9 db [2] eb da [2] f0 dc [2] ec db [2] f0 f4 }

  condition:
    any of them
}