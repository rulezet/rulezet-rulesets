rule TTP_XOR_QUAD_CurrentVersionRun_9eae {
  strings:
    $key_9eae = { cd c1 [2] e9 cf [2] c2 e3 [2] ec c1 [2] f8 da [2] f7 c0 [2] e9 dd [2] eb dc [2] f0 da [2] ec dd [2] f0 f2 }

  condition:
    any of them
}